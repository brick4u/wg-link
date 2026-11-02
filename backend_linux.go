package wglink

import (
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ownerAlias = "wg-link:v1"
const routeProtocol = 196
const routeMetric = 42760

type DesiredPeer struct {
	Config   wgtypes.PeerConfig
	Endpoint *net.UDPAddr
}
type DesiredInterface struct {
	Interface Interface
	Peers     []DesiredPeer
}
type Backend interface {
	Apply([]DesiredInterface) error
	Devices() ([]*wgtypes.Device, error)
}
type LinuxBackend struct {
	forwarding       forwardingState
	wg               *wgctrl.Client
	appliedEndpoints map[string]map[wgtypes.Key]string
}

func NewLinuxBackend() (*LinuxBackend, error) {
	w, e := wgctrl.New()
	return &LinuxBackend{wg: w, appliedEndpoints: map[string]map[wgtypes.Key]string{}}, e
}

// preparePeers uses per-interface successful declarations, not the outcome of a later
// interface, to preserve authenticated roaming when a multi-interface Apply retries.
func preparePeers(desired []DesiredPeer, current []wgtypes.Peer, applied map[wgtypes.Key]string) ([]wgtypes.PeerConfig, map[wgtypes.Key]string) {
	existing := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range current {
		existing[p.PublicKey] = p
	}
	next := map[wgtypes.Key]string{}
	configs := []wgtypes.PeerConfig{}
	for _, p := range desired {
		pc := p.Config
		endpoint := p.Endpoint
		if endpoint == nil {
			endpoint = pc.Endpoint
		}
		next[pc.PublicKey] = applied[pc.PublicKey]
		if endpoint != nil {
			declaration := endpoint.String()
			next[pc.PublicKey] = declaration
			if applied[pc.PublicKey] == declaration && existing[pc.PublicKey].Endpoint != nil {
				pc.Endpoint = nil
			} else {
				pc.Endpoint = endpoint
			}
		}
		configs = append(configs, pc)
		delete(existing, pc.PublicKey)
	}
	for key := range existing {
		configs = append(configs, wgtypes.PeerConfig{PublicKey: key, Remove: true})
	}
	return configs, next
}
func (b *LinuxBackend) Close() error { return b.wg.Close() }
func (b *LinuxBackend) Devices() ([]*wgtypes.Device, error) {
	links, e := netlink.LinkList()
	if e != nil {
		return nil, e
	}
	var devices []*wgtypes.Device
	for _, l := range links {
		if l.Type() != "wireguard" || l.Attrs().Alias != ownerAlias {
			continue
		}
		d, e := b.wg.Device(l.Attrs().Name)
		if e != nil {
			return nil, e
		}
		devices = append(devices, d)
	}
	return devices, nil
}
func routeFor(prefix string, blackhole bool, index int) netlink.Route {
	_, n, _ := net.ParseCIDR(prefix)
	r := netlink.Route{Dst: n, Table: unix.RT_TABLE_MAIN, Protocol: routeProtocol, Priority: routeMetric, LinkIndex: index}
	if blackhole {
		r.Type = unix.RTN_BLACKHOLE
		r.LinkIndex = 0
		r.Priority = routeMetric + 1
	}
	return r
}
func ensureRoute(r netlink.Route) error {
	routes, e := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: r.Table}, netlink.RT_FILTER_TABLE)
	if e != nil {
		return e
	}
	for _, existing := range routes {
		prefix := existing.Dst
		if prefix == nil {
			if existing.Family == netlink.FAMILY_V6 {
				_, prefix, _ = net.ParseCIDR("::/0")
			} else {
				_, prefix, _ = net.ParseCIDR("0.0.0.0/0")
			}
		}
		ebits, _ := prefix.Mask.Size()
		rbits, _ := r.Dst.Mask.Size()
		if ebits < rbits || !r.Dst.Contains(prefix.IP) {
			continue
		}
		if existing.Protocol == routeProtocol {
			continue
		}
		// Connected routes on owned links disappear with the link and remain encrypted.
		if existing.Protocol == unix.RTPROT_KERNEL && existing.LinkIndex != 0 {
			l, e := netlink.LinkByIndex(existing.LinkIndex)
			if e != nil {
				return e
			}
			if l.Type() == "wireguard" && l.Attrs().Alias == ownerAlias {
				continue
			}
		}
		return fmt.Errorf("foreign route overlaps protected prefix")
	}
	return netlink.RouteReplace(&r)
}
func (b *LinuxBackend) Apply(desired []DesiredInterface) error {
	// Install persistent guards before touching peers or interfaces. Tombstones intentionally survive config removal.
	for _, d := range desired {
		for _, r := range d.Interface.Routes {
			if e := ensureRoute(routeFor(r, true, 0)); e != nil {
				return fmt.Errorf("install fail-closed route: %w", e)
			}
		}
	}
	wanted := map[string]bool{}
	for _, d := range desired {
		n := d.Interface
		wanted[n.Name] = true
		l, e := netlink.LinkByName(n.Name)
		if e != nil {
			if _, ok := e.(netlink.LinkNotFoundError); !ok {
				return e
			}
			l = &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: n.Name, Alias: ownerAlias, MTU: n.MTU}}
			if e = netlink.LinkAdd(l); e != nil {
				return e
			}
			l, e = netlink.LinkByName(n.Name)
			if e != nil {
				return e
			}
			// netlink.LinkAdd does not consistently send IFLA_IFALIAS for new links.
			// Only mark the link we just successfully created, never adopt an existing link.
			if e = netlink.LinkSetAlias(l, ownerAlias); e != nil {
				_ = netlink.LinkDel(l)
				return fmt.Errorf("set interface ownership: %w", e)
			}
			l, e = netlink.LinkByName(n.Name)
			if e != nil {
				return e
			}
		}
		if l.Type() != "wireguard" || l.Attrs().Alias != ownerAlias {
			return fmt.Errorf("refusing foreign interface %s", n.Name)
		}
		if e = netlink.LinkSetMTU(l, n.MTU); e != nil {
			return e
		}
		current, e := b.wg.Device(n.Name)
		if e != nil {
			return e
		}
		peers, applied := preparePeers(d.Peers, current.Peers, b.appliedEndpoints[n.Name])
		port := n.ListenPort
		if port == 0 && current.ListenPort != 0 {
			port = current.ListenPort
		}
		if e = b.wg.ConfigureDevice(n.Name, wgtypes.Config{PrivateKey: &n.key, ListenPort: &port, Peers: peers}); e != nil {
			return e
		}
		if b.appliedEndpoints == nil {
			b.appliedEndpoints = map[string]map[wgtypes.Key]string{}
		}
		b.appliedEndpoints[n.Name] = applied
		addresses, e := netlink.AddrList(l, netlink.FAMILY_ALL)
		if e != nil {
			return e
		}
		wantedAddr := map[string]bool{}
		for _, a := range n.Addresses {
			addr, e := netlink.ParseAddr(a)
			if e != nil {
				return e
			}
			wantedAddr[addr.String()] = true
			if e = netlink.AddrReplace(l, addr); e != nil {
				return e
			}
		}
		for _, a := range addresses {
			if a.IP.IsLinkLocalUnicast() {
				continue
			}
			if !wantedAddr[a.String()] {
				if e = netlink.AddrDel(l, &a); e != nil {
					return e
				}
			}
		}
		if e = netlink.LinkSetUp(l); e != nil {
			return e
		}
		desiredRoutes := map[string]bool{}
		for _, r := range n.Routes {
			desiredRoutes[r] = true
			if e = ensureRoute(routeFor(r, false, l.Attrs().Index)); e != nil {
				return e
			}
		}
		routes, e := netlink.RouteList(l, netlink.FAMILY_ALL)
		if e != nil {
			return e
		}
		for _, r := range routes {
			if r.Protocol == routeProtocol && r.Priority == routeMetric && r.Dst != nil && !desiredRoutes[r.Dst.String()] {
				if e = netlink.RouteDel(&r); e != nil {
					return e
				}
			}
		}
	}
	links, e := netlink.LinkList()
	if e != nil {
		return e
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Attrs().Name < links[j].Attrs().Name })
	for _, l := range links {
		if l.Attrs().Alias == ownerAlias && l.Type() == "wireguard" && !wanted[l.Attrs().Name] {
			if e = netlink.LinkDel(l); e != nil {
				return e
			}
		}
	}
	return nil
}
