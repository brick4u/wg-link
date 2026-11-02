package wglink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const nftOwner = "wg-link:v1"

type nftRunner func(context.Context, string, ...string) ([]byte, error)
type forwardingState struct {
	run       nftRunner
	readFile  func(string) ([]byte, error)
	writeFile func(string, []byte, os.FileMode) error
	last      string
}

func runNFT(ctx context.Context, input string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft command failed: %w: %s", err, bytes.TrimSpace(out))
	}
	return out, nil
}
func (b *LinuxBackend) ApplyForwarding(c *Config) error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	declared := map[string]bool{}
	for _, n := range c.Interfaces {
		declared[n.Name] = true
	}
	// Check ownership before changing a firewall boundary or any sysctl.
	for _, l := range links {
		owned := l.Type() == "wireguard" && l.Attrs().Alias == ownerAlias
		if declared[l.Attrs().Name] && !owned {
			return fmt.Errorf("refusing foreign interface %s", l.Attrs().Name)
		}
		if owned && !declared[l.Attrs().Name] {
			// Also guard stale owned links until Apply removes them.
			copyConfig := *c
			copyConfig.Interfaces = append(append([]Interface(nil), c.Interfaces...), Interface{Name: l.Attrs().Name})
			c = &copyConfig
			declared[l.Attrs().Name] = true
		}
	}
	return b.forwarding.apply(c)
}
func (s *forwardingState) apply(c *Config) error {
	if err := validateForwarding(c); err != nil {
		return err
	}
	if s.run == nil {
		s.run = runNFT
	}
	if s.readFile == nil {
		s.readFile = os.ReadFile
	}
	if s.writeFile == nil {
		s.writeFile = os.WriteFile
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Discover by listing, not by interpreting a failed lookup as an absent table.
	out, err := s.run(ctx, "", "-j", "list", "tables")
	if err != nil {
		return err
	}
	var tables struct {
		NFTables []struct {
			Table *struct{ Family, Name string }
		} `json:"nftables"`
	}
	if err = json.Unmarshal(out, &tables); err != nil {
		return fmt.Errorf("decode nft tables: %w", err)
	}
	exists := false
	for _, v := range tables.NFTables {
		if v.Table != nil && v.Table.Family == "inet" && v.Table.Name == "wg_link" {
			exists = true
		}
	}
	names := map[string]bool{}
	if exists {
		out, err = s.run(ctx, "", "-j", "list", "table", "inet", "wg_link")
		if err != nil {
			return err
		}
		var table struct {
			NFTables []struct {
				Table *struct{ Family, Name, Comment string }
				Set   *struct {
					Name string
					Elem []string
				}
			} `json:"nftables"`
		}
		if err = json.Unmarshal(out, &table); err != nil {
			return fmt.Errorf("decode owned nft table: %w", err)
		}
		owned := false
		for _, v := range table.NFTables {
			if v.Table != nil && v.Table.Family == "inet" && v.Table.Name == "wg_link" && v.Table.Comment == nftOwner {
				owned = true
			}
			if v.Set != nil && v.Set.Name == "owned_interfaces" {
				for _, n := range v.Set.Elem {
					if !interfaceName.MatchString(n) {
						return fmt.Errorf("invalid owned nft interface")
					}
					names[n] = true
				}
			}
		}
		if !owned {
			return fmt.Errorf("refusing foreign nft table inet wg_link")
		}
	}
	enabled := c.Forwarding != nil && c.Forwarding.Enabled
	// An untouched deployment does not require nft, but must detect a retained boundary on restart.
	if !enabled && !exists && s.last == "" {
		return nil
	}
	for _, n := range c.Interfaces {
		names[n.Name] = true
	}
	batch := renderForwarding(c, names)
	if !exists || batch != s.last {
		input := batch
		if exists {
			input = "delete table inet wg_link\n" + input
		}
		if _, err = s.run(ctx, input, "-f", "-"); err != nil {
			return err
		}
		s.last = batch
	}
	if enabled {
		families := map[bool]bool{}
		for _, r := range c.Forwarding.Rules {
			p, _ := netip.ParsePrefix(r.Source)
			families[p.Addr().Is4()] = true
		}
		for _, ipv4 := range []bool{true, false} {
			if !families[ipv4] {
				continue
			}
			path := "/proc/sys/net/ipv6/conf/all/forwarding"
			key := "net.ipv6.conf.all.forwarding"
			if ipv4 {
				path = "/proc/sys/net/ipv4/ip_forward"
				key = "net.ipv4.ip_forward"
			}
			value, e := s.readFile(path)
			if e != nil {
				return fmt.Errorf("read forwarding sysctl %s: %w", key, e)
			}
			if strings.TrimSpace(string(value)) == "1" {
				continue
			}
			if e = s.writeFile(path, []byte("1\n"), 0644); e != nil {
				return fmt.Errorf("enable %s: %w; preconfigure Pod securityContext.sysctls (subject to cluster admission); NET_ADMIN cannot bypass read-only /proc/sys", key, e)
			}
			value, e = s.readFile(path)
			if e != nil || strings.TrimSpace(string(value)) != "1" {
				return fmt.Errorf("forwarding sysctl %s did not become 1", key)
			}
		}
	}
	return nil
}
func renderForwarding(c *Config, names map[string]bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet wg_link { comment %q; }\n", nftOwner)
	ns := make([]string, 0, len(names))
	for n := range names {
		ns = append(ns, strconv.Quote(n))
	}
	sort.Strings(ns)
	fmt.Fprintf(&b, "add set inet wg_link owned_interfaces { type ifname; elements = { %s }; }\n", strings.Join(ns, ", "))
	b.WriteString("add chain inet wg_link forward { type filter hook forward priority 0; policy accept; }\n")
	if c.Forwarding != nil && c.Forwarding.Enabled {
		for _, r := range c.Forwarding.Rules {
			prefix, _ := netip.ParsePrefix(r.Source)
			family := "ip"
			if !prefix.Addr().Is4() {
				family = "ip6"
			}
			for _, proto := range r.Protocols {
				nftproto := proto
				if proto == "icmpv6" {
					nftproto = "ipv6-icmp"
				}
				ports := ""
				reversePorts := ""
				if len(r.Ports) > 0 {
					ps := []string{}
					for _, p := range r.Ports {
						ps = append(ps, strconv.Itoa(p))
					}
					ports = fmt.Sprintf(" %s dport { %s }", proto, strings.Join(ps, ", "))
					reversePorts = fmt.Sprintf(" %s sport { %s }", proto, strings.Join(ps, ", "))
				}
				fmt.Fprintf(&b, "add rule inet wg_link forward iifname %q oifname %q %s saddr %s %s daddr %s meta l4proto %s%s ct state { new, established } counter accept\n", r.From, r.To, family, r.Source, family, r.Destination, nftproto, ports)
				// Reverse replies remain tied to the current ACL, including both interfaces,
				// prefixes and service ports. No global conntrack bypass survives revocation.
				fmt.Fprintf(&b, "add rule inet wg_link forward iifname %q oifname %q %s saddr %s %s daddr %s meta l4proto %s%s ct state established counter accept\n", r.To, r.From, family, r.Destination, family, r.Source, nftproto, reversePorts)
			}
		}
	}
	b.WriteString("add rule inet wg_link forward iifname @owned_interfaces counter drop\nadd rule inet wg_link forward oifname @owned_interfaces counter drop\nadd rule inet wg_link forward return\n")
	return b.String()
}
