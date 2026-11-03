package wglink

import (
	"fmt"
	"net/netip"
)

// Forwarding is opt-in, namespace-local routing between explicitly scoped links.
type Forwarding struct {
	Enabled            bool             `yaml:"enabled"`
	ExternalInterfaces []string         `yaml:"externalInterfaces"`
	Rules              []ForwardRule    `yaml:"rules"`
	Masquerade         []MasqueradeRule `yaml:"masquerade"`
}
type MasqueradeRule struct {
	From        string `yaml:"from"`
	To          string `yaml:"to"`
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
}

type ForwardRule struct {
	From        string   `yaml:"from"`
	To          string   `yaml:"to"`
	Source      string   `yaml:"source"`
	Destination string   `yaml:"destination"`
	Protocols   []string `yaml:"protocols"`
	Ports       []int    `yaml:"ports"`
}

func validateForwarding(c *Config) error {
	f := c.Forwarding
	if f == nil {
		return nil
	}
	if !f.Enabled && (len(f.Rules) > 0 || len(f.Masquerade) > 0) {
		return fmt.Errorf("disabled forwarding must not contain rules or masquerade")
	}
	names := map[string]bool{}
	for _, n := range c.Interfaces {
		names[n.Name] = true
	}
	for _, n := range f.ExternalInterfaces {
		if !validForwardInterface(n) || names[n] {
			return fmt.Errorf("externalInterfaces requires unique valid names distinct from declared WireGuard interfaces")
		}
		names[n] = true
	}
	for _, r := range f.Masquerade {
		if !names[r.From] || !names[r.To] || !validForwardInterface(r.From) || !validForwardInterface(r.To) {
			return fmt.Errorf("masquerade requires declared WireGuard or external interfaces")
		}
		s, se := netip.ParsePrefix(r.Source)
		d, de := netip.ParsePrefix(r.Destination)
		if se != nil || de != nil || s != s.Masked() || d != d.Masked() || !s.Addr().Is4() || !d.Addr().Is4() {
			return fmt.Errorf("masquerade requires explicit canonical IPv4 source and destination CIDRs; IPv6 is unsupported")
		}
	}
	for _, r := range f.Rules {
		if !names[r.From] || !names[r.To] || !validForwardInterface(r.From) || !validForwardInterface(r.To) {
			return fmt.Errorf("forwarding requires declared WireGuard or external interfaces")
		}
		s, se := netip.ParsePrefix(r.Source)
		d, de := netip.ParsePrefix(r.Destination)
		if se != nil || de != nil || s != s.Masked() || d != d.Masked() || s.Addr().Is4() != d.Addr().Is4() || s.Addr().Is4In6() || d.Addr().Is4In6() {
			return fmt.Errorf("forwarding requires canonical same-family CIDRs")
		}
		if len(r.Protocols) == 0 {
			return fmt.Errorf("forwarding requires explicit protocols")
		}
		protocols := map[string]bool{}
		for _, p := range r.Protocols {
			if protocols[p] {
				return fmt.Errorf("duplicate forwarding protocol")
			}
			protocols[p] = true
			switch p {
			case "tcp", "udp":
			case "icmp":
				if !s.Addr().Is4() {
					return fmt.Errorf("icmp requires IPv4")
				}
			case "icmpv6":
				if s.Addr().Is4() {
					return fmt.Errorf("icmpv6 requires IPv6")
				}
			default:
				return fmt.Errorf("invalid forwarding protocol")
			}
			if len(r.Ports) > 0 && p != "tcp" && p != "udp" {
				return fmt.Errorf("ports require only TCP/UDP protocols")
			}
		}
		ports := map[int]bool{}
		for _, p := range r.Ports {
			if p < 1 || p > 65535 || ports[p] {
				return fmt.Errorf("forwarding ports must be unique integers 1..65535")
			}
			ports[p] = true
		}
	}
	return nil
}

func validForwardInterface(n string) bool {
	return interfaceName.MatchString(n) && n != "." && n != ".."
}
