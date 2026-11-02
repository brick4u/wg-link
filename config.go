package wglink

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	Interfaces []Interface `yaml:"interfaces"`
	Forwarding *Forwarding `yaml:"forwarding"`
}
type Interface struct {
	Name           string   `yaml:"name"`
	Addresses      []string `yaml:"addresses"`
	MTU            int      `yaml:"mtu"`
	ListenPort     int      `yaml:"listenPort"`
	PrivateKeyFile string   `yaml:"privateKeyFile"`
	Routes         []string `yaml:"routes"`
	Peers          []Peer   `yaml:"peers"`
	key            wgtypes.Key
}
type ServiceRef struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
	Port      string `yaml:"port"`
}
type Peer struct {
	PublicKey           string      `yaml:"publicKey"`
	PresharedKeyFile    string      `yaml:"presharedKeyFile"`
	AllowedIPs          []string    `yaml:"allowedIPs"`
	PersistentKeepalive int         `yaml:"persistentKeepalive"`
	Endpoint            string      `yaml:"endpoint"`
	Service             *ServiceRef `yaml:"service"`
	key                 wgtypes.Key
	psk                 wgtypes.Key
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func Load(path string) (*Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, fmt.Errorf("read config: %w", e)
	}
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return nil, fmt.Errorf("invalid YAML configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("expected one YAML document")
	}
	if len(c.Interfaces) == 0 {
		return nil, fmt.Errorf("interfaces must not be empty")
	}
	names := map[string]bool{}
	routes := map[string]bool{}
	for i := range c.Interfaces {
		n := &c.Interfaces[i]
		if !interfaceName.MatchString(n.Name) || n.Name == "." || n.Name == ".." || names[n.Name] {
			return nil, fmt.Errorf("invalid or duplicate interface name")
		}
		names[n.Name] = true
		if n.MTU == 0 {
			n.MTU = 1280
		}
		if n.MTU < 576 || n.MTU > 65535 || n.ListenPort < 0 || n.ListenPort > 65535 {
			return nil, fmt.Errorf("invalid MTU or listenPort for %s", n.Name)
		}
		var err error
		n.key, err = loadRelativeKey(path, n.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("interface %s private key unavailable or invalid", n.Name)
		}
		for _, a := range n.Addresses {
			if _, err := netip.ParsePrefix(a); err != nil {
				return nil, fmt.Errorf("invalid interface address")
			}
		}
		for _, r := range n.Routes {
			p, err := netip.ParsePrefix(r)
			if err != nil || p != p.Masked() {
				return nil, fmt.Errorf("routes must be canonical CIDRs")
			}
			if routes[r] {
				return nil, fmt.Errorf("duplicate route")
			}
			routes[r] = true
		}
		keys := map[string]bool{}
		allowed := map[string]bool{}
		for j := range n.Peers {
			p := &n.Peers[j]
			p.key, err = wgtypes.ParseKey(p.PublicKey)
			if err != nil || p.key == (wgtypes.Key{}) || keys[p.PublicKey] {
				return nil, fmt.Errorf("invalid or duplicate peer key")
			}
			keys[p.PublicKey] = true
			if p.PresharedKeyFile != "" {
				p.psk, err = loadRelativeKey(path, p.PresharedKeyFile)
				if err != nil {
					return nil, fmt.Errorf("peer preshared key unavailable or invalid")
				}
			}
			if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
				return nil, fmt.Errorf("invalid keepalive")
			}
			for _, a := range p.AllowedIPs {
				v, e := netip.ParsePrefix(a)
				if e != nil || v != v.Masked() || allowed[a] {
					return nil, fmt.Errorf("allowedIPs must be unique canonical CIDRs per interface")
				}
				allowed[a] = true
			}
			if p.Service != nil {
				if p.Endpoint != "" || p.Service.Namespace == "" || p.Service.Name == "" || p.Service.Port == "" {
					return nil, fmt.Errorf("invalid service reference")
				}
			}
			if p.Endpoint != "" {
				if _, err := parseEndpoint(p.Endpoint); err != nil {
					return nil, fmt.Errorf("endpoint requires literal IP and port")
				}
			}
		}
	}
	if err := validateForwarding(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
func loadRelativeKey(config, path string) (wgtypes.Key, error) {
	if path == "" {
		return wgtypes.Key{}, fmt.Errorf("empty key path")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(config), path)
	}
	return readKeyFile(path)
}
func readKeyFile(path string) (wgtypes.Key, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return wgtypes.Key{}, e
	}
	k, e := wgtypes.ParseKey(string(bytes.TrimSpace(b)))
	if k == (wgtypes.Key{}) {
		return k, fmt.Errorf("zero key")
	}
	return k, e
}
func parseEndpoint(s string) (*net.UDPAddr, error) {
	a, e := netip.ParseAddrPort(s)
	if e != nil || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
		return nil, fmt.Errorf("invalid endpoint")
	}
	return net.UDPAddrFromAddrPort(a), nil
}
func keepalive(n int) *time.Duration { d := time.Duration(n) * time.Second; return &d }
