package wglink

import (
	"fmt"
	"net/netip"

	"go.yaml.in/yaml/v3"
)

// Forwarding is opt-in, namespace-local routing between explicitly scoped links.
type Forwarding struct {
	Enabled            bool             `yaml:"enabled"`
	ExternalInterfaces []string         `yaml:"externalInterfaces"`
	Rules              []ForwardRule    `yaml:"rules"`
	Masquerade         []MasqueradeRule `yaml:"masquerade"`
	DNAT               []DNATRule       `yaml:"dnat"`
}

// DNATRule translates an explicitly scoped IPv4 destination; forwarding ACLs
// independently authorize the translated destination and service port.
type DNATRule struct {
	From            string `yaml:"from"`
	Source          string `yaml:"source"`
	Destination     string `yaml:"destination"`
	Protocol        string `yaml:"protocol"`
	Port            int    `yaml:"port"`
	TargetIPAddress string `yaml:"targetIPAddress"`
	TargetPort      int    `yaml:"targetPort"`
}

// UnmarshalYAML prevents YAML's float-to-int coercion for service ports.
// Node.Decode does not inherit the outer decoder's KnownFields setting, so
// reject unknown fields here as well.
func (r *DNATRule) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("dnat entry must be a mapping")
	}
	for i := 0; i < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		switch key.Value {
		case "from", "source", "destination", "protocol", "targetIPAddress":
		case "port", "targetPort":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!int" {
				return fmt.Errorf("dnat %s must be an integer", key.Value)
			}
		default:
			return fmt.Errorf("unknown dnat field %q", key.Value)
		}
	}
	type plain DNATRule
	return n.Decode((*plain)(r))
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
	if !f.Enabled && (len(f.Rules) > 0 || len(f.Masquerade) > 0 || len(f.DNAT) > 0) {
		return fmt.Errorf("disabled forwarding must not contain rules, masquerade or dnat")
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
	for i, r := range f.DNAT {
		if !names[r.From] || !validForwardInterface(r.From) {
			return fmt.Errorf("dnat requires a declared WireGuard or external ingress interface")
		}
		s, se := netip.ParsePrefix(r.Source)
		d, de := netip.ParsePrefix(r.Destination)
		if se != nil || de != nil || !s.Addr().Is4() || !d.Addr().Is4() || s != s.Masked() || d != d.Masked() || s.String() != r.Source || d.String() != r.Destination || d.Bits() != 32 {
			return fmt.Errorf("dnat requires canonical IPv4 source and destination CIDRs, with destination /32")
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("dnat protocol must be tcp or udp")
		}
		if r.Port < 1 || r.Port > 65535 || r.TargetPort < 1 || r.TargetPort > 65535 {
			return fmt.Errorf("dnat port and targetPort must be integers 1..65535")
		}
		target, err := netip.ParseAddr(r.TargetIPAddress)
		if err != nil || !target.Is4() {
			return fmt.Errorf("dnat targetIPAddress must be a literal IPv4 address")
		}
		for _, prior := range f.DNAT[:i] {
			ps, _ := netip.ParsePrefix(prior.Source)
			if r.From == prior.From && r.Destination == prior.Destination && r.Protocol == prior.Protocol && r.Port == prior.Port && s.Overlaps(ps) {
				return fmt.Errorf("dnat rules must not have duplicate or overlapping matches")
			}
		}
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
