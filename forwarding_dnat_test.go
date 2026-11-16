package wglink

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func dnatForwardingConfig() *Config {
	c := forwardingConfig()
	c.Forwarding.ExternalInterfaces = []string{"eth0"}
	c.Forwarding.Rules = []ForwardRule{{From: "eth0", To: "wg-b", Source: "198.18.10.0/24", Destination: "198.18.60.1/32", Protocols: []string{"tcp"}, Ports: []int{1883}}}
	c.Forwarding.DNAT = []DNATRule{{From: "eth0", Source: "198.18.10.0/24", Destination: "192.0.2.80/32", Protocol: "tcp", Port: 12101, TargetIPAddress: "198.18.60.1", TargetPort: 1883}}
	return c
}

func TestDNATValidation(t *testing.T) {
	if err := validateForwarding(dnatForwardingConfig()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DNATRule){
		"undeclared ingress":    func(r *DNATRule) { r.From = "eth1" },
		"invalid ingress":       func(r *DNATRule) { r.From = "eth0;accept" },
		"missing source":        func(r *DNATRule) { r.Source = "" },
		"source host bits":      func(r *DNATRule) { r.Source = "198.18.10.1/24" },
		"source address":        func(r *DNATRule) { r.Source = "198.18.10.1" },
		"IPv6 source":           func(r *DNATRule) { r.Source = "2001:db8::/64" },
		"mapped source":         func(r *DNATRule) { r.Source = "::ffff:198.18.10.0/120" },
		"missing destination":   func(r *DNATRule) { r.Destination = "" },
		"destination network":   func(r *DNATRule) { r.Destination = "192.0.2.0/24" },
		"destination host bits": func(r *DNATRule) { r.Destination = "192.0.2.80/24" },
		"IPv6 destination":      func(r *DNATRule) { r.Destination = "2001:db8::1/128" },
		"missing protocol":      func(r *DNATRule) { r.Protocol = "" },
		"icmp":                  func(r *DNATRule) { r.Protocol = "icmp" },
		"uppercase":             func(r *DNATRule) { r.Protocol = "TCP" },
		"port zero":             func(r *DNATRule) { r.Port = 0 },
		"port negative":         func(r *DNATRule) { r.Port = -1 },
		"port overflow":         func(r *DNATRule) { r.Port = 65536 },
		"missing target":        func(r *DNATRule) { r.TargetIPAddress = "" },
		"hostname target":       func(r *DNATRule) { r.TargetIPAddress = "proxy.example" },
		"CIDR target":           func(r *DNATRule) { r.TargetIPAddress = "198.18.60.1/32" },
		"IPv6 target":           func(r *DNATRule) { r.TargetIPAddress = "2001:db8::1" },
		"mapped target":         func(r *DNATRule) { r.TargetIPAddress = "::ffff:198.18.60.1" },
		"target injection":      func(r *DNATRule) { r.TargetIPAddress = "198.18.60.1; accept" },
		"target port zero":      func(r *DNATRule) { r.TargetPort = 0 },
		"target port negative":  func(r *DNATRule) { r.TargetPort = -1 },
		"target port overflow":  func(r *DNATRule) { r.TargetPort = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			c := dnatForwardingConfig()
			mutate(&c.Forwarding.DNAT[0])
			if validateForwarding(c) == nil {
				t.Fatal("accepted invalid DNAT")
			}
		})
	}
	c := dnatForwardingConfig()
	c.Forwarding.Enabled = false
	c.Forwarding.Rules = nil
	if validateForwarding(c) == nil {
		t.Fatal("accepted disabled DNAT")
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, port := range []int{1, 65535} {
			c := dnatForwardingConfig()
			r := &c.Forwarding.DNAT[0]
			r.From, r.Source, r.Protocol, r.Port, r.TargetPort = "wg-a", "0.0.0.0/0", proto, port, port
			if err := validateForwarding(c); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDNATOverlappingMatches(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*DNATRule)
		valid  bool
	}{
		{"identical", func(*DNATRule) {}, false},
		{"different target", func(r *DNATRule) { r.TargetIPAddress = "198.18.60.2" }, false},
		{"different target port", func(r *DNATRule) { r.TargetPort = 1884 }, false},
		{"narrower source", func(r *DNATRule) { r.Source = "198.18.10.128/25" }, false},
		{"wider source", func(r *DNATRule) { r.Source = "198.18.0.0/16" }, false},
		{"disjoint source", func(r *DNATRule) { r.Source = "198.18.11.0/24" }, true},
		{"different original port", func(r *DNATRule) { r.Port = 12102 }, true},
		{"different original destination", func(r *DNATRule) { r.Destination = "192.0.2.81/32" }, true},
		{"different protocol", func(r *DNATRule) { r.Protocol = "udp" }, true},
		{"different ingress", func(r *DNATRule) { r.From = "wg-a" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dnatForwardingConfig()
			r := c.Forwarding.DNAT[0]
			tc.mutate(&r)
			c.Forwarding.DNAT = append(c.Forwarding.DNAT, r)
			if err := validateForwarding(c); (err == nil) != tc.valid {
				t.Fatalf("validation error=%v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestDNATSchema(t *testing.T) {
	path, base := fixture(t)
	dnat := `forwarding:
  enabled: true
  externalInterfaces: [eth0]
  dnat:
    - from: eth0
      source: 198.18.10.0/24
      destination: 192.0.2.80/32
      protocol: tcp
      port: 12101
      targetIPAddress: 198.18.60.1
      targetPort: 1883
`
	for _, tc := range []struct {
		name, config string
		valid        bool
	}{
		{"exact schema", dnat, true},
		{"missing targetPort", strings.Replace(dnat, "      targetPort: 1883\n", "", 1), false},
		{"noninteger targetPort", strings.Replace(dnat, "targetPort: 1883", "targetPort: invalid", 1), false},
		{"fractional targetPort", strings.Replace(dnat, "targetPort: 1883", "targetPort: 1883.5", 1), false},
		{"fractional original port", strings.Replace(dnat, "port: 12101", "port: 12101.5", 1), false},
		{"null targetPort", strings.Replace(dnat, "targetPort: 1883", "targetPort: null", 1), false},
		{"quoted targetPort", strings.Replace(dnat, "targetPort: 1883", "targetPort: '1883'", 1), false},
		{"duplicate DNAT field", strings.Replace(dnat, "      targetPort: 1883", "      targetPort: 1883\n      targetPort: 1884", 1), false},
		{"unknown target field", strings.Replace(dnat, "targetIPAddress:", "target:", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(base+tc.config), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("Load error=%v, want valid=%v", err, tc.valid)
			}
			if err == nil && c.Forwarding.DNAT[0].TargetPort != 1883 {
				t.Fatal("target port not decoded")
			}
		})
	}
}

func TestDNATRender(t *testing.T) {
	c := dnatForwardingConfig()
	batch := renderForwarding(c, map[string]bool{"eth0": true, "wg-b": true})
	for _, want := range []string{
		"type nat hook prerouting priority dstnat; policy accept",
		`prerouting iifname "eth0" ip saddr 198.18.10.0/24 ip daddr 192.0.2.80/32 tcp dport 12101 counter dnat ip to 198.18.60.1:1883`,
		`forward iifname "eth0" oifname "wg-b" ip saddr 198.18.10.0/24 ip daddr 198.18.60.1/32 meta l4proto tcp tcp dport { 1883 } ct state { new, established } counter accept`,
		`forward iifname "wg-b" oifname "eth0" ip saddr 198.18.60.1/32 ip daddr 198.18.10.0/24 meta l4proto tcp tcp sport { 1883 } ct state established counter accept`,
	} {
		if !strings.Contains(batch, want) {
			t.Fatalf("missing %s in %s", want, batch)
		}
	}
	for _, unwanted := range []string{"masquerade", "snat", "hook output", "flush ruleset", "related"} {
		if strings.Contains(batch, unwanted) {
			t.Fatalf("unexpected %s in %s", unwanted, batch)
		}
	}
	c.Forwarding.Rules = nil
	if b := renderForwarding(c, map[string]bool{"eth0": true}); strings.Contains(b, "counter accept") || !strings.Contains(b, "counter dnat") {
		t.Fatal("DNAT granted forwarding permission", b)
	}
	c.Forwarding.DNAT[0].Protocol = "udp"
	if b := renderForwarding(c, map[string]bool{"eth0": true}); !strings.Contains(b, "udp dport 12101 counter dnat") {
		t.Fatal(b)
	}
	c.Forwarding.Enabled = false
	if b := renderForwarding(c, map[string]bool{"eth0": true}); strings.Contains(b, "type nat") || strings.Contains(b, "dnat") {
		t.Fatal(b)
	}
}

func TestDNATStagingFailures(t *testing.T) {
	for _, failure := range []string{"missing link", "backend", "commit", "link disappears", "sysctl"} {
		t.Run(failure, func(t *testing.T) {
			b := &stagedForwardingBackend{}
			var installed []string
			b.state.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
				if input != "" {
					if failure == "commit" && strings.Contains(input, "counter dnat") {
						return nil, errors.New("atomic nft failure")
					}
					installed = append(installed, input)
					return nil, nil
				}
				return []byte(`{"nftables":[]}`), nil
			}
			checks := 0
			b.state.externalExists = func(string) error {
				checks++
				if failure == "missing link" || (failure == "link disappears" && checks > 1) {
					return errors.New("not found")
				}
				return nil
			}
			b.state.readFile = func(string) ([]byte, error) {
				if failure == "sysctl" {
					return []byte("0"), nil
				}
				return []byte("1"), nil
			}
			b.state.writeFile = func(string, []byte, os.FileMode) error { return errors.New("read-only") }
			if failure == "backend" {
				b.err = errors.New("route failure")
			}
			if err := (&Agent{Backend: b}).Reconcile(dnatForwardingConfig()); err == nil {
				t.Fatal("expected failure")
			}
			if len(installed) != 1 || strings.Contains(installed[0], "type nat") || strings.Contains(installed[0], "ct state") || !strings.Contains(installed[0], `"eth0"`) {
				t.Fatalf("failure did not retain scoped deny without NAT: %v", installed)
			}
		})
	}
}

func TestDNATRemovalAndDisable(t *testing.T) {
	s := forwardingState{}
	exists := false
	var installed []string
	s.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
		if input != "" {
			exists = true
			installed = append(installed, input)
			return nil, nil
		}
		if args[len(args)-1] == "tables" {
			if exists {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link"}}]}`), nil
			}
			return []byte(`{"nftables":[]}`), nil
		}
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link","comment":"wg-link:v1"}},{"set":{"name":"owned_interfaces","elem":["eth0","wg-b","wg-old"]}}]}`), nil
	}
	s.externalExists = func(string) error { return nil }
	s.readFile = func(string) ([]byte, error) { return []byte("1"), nil }
	c := dnatForwardingConfig()
	for i := 0; i < 2; i++ {
		if err := s.apply(c); err != nil {
			t.Fatal(err)
		}
		if i == 0 && (len(installed) != 1 || strings.Contains(installed[0], "type nat")) {
			t.Fatal("NAT enabled before commit", installed)
		}
		if err := s.commit(); err != nil {
			t.Fatal(err)
		}
	}
	// Discovery of the historical wg-old interface adds it to the boundary on the
	// second apply. A third unchanged apply must not touch the table.
	before := len(installed)
	if err := s.apply(c); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(); err != nil {
		t.Fatal(err)
	}
	if len(installed) != before {
		t.Fatal("unchanged DNAT churned", installed)
	}
	c.Forwarding.DNAT = nil
	c.Forwarding.Rules = nil
	if err := s.apply(c); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(); err != nil {
		t.Fatal(err)
	}
	last := installed[len(installed)-1]
	if strings.Contains(last, "type nat") || strings.Contains(last, "ct state") || !strings.Contains(last, `"wg-old"`) {
		t.Fatal("removal lost deny boundary", last)
	}
	c.Forwarding = nil
	if err := s.apply(c); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(); err != nil {
		t.Fatal(err)
	}
	last = installed[len(installed)-1]
	if strings.Contains(last, "type nat") || !strings.Contains(last, `"eth0"`) {
		t.Fatal(last)
	}
}

func TestDNATAloneRequiresIPv4Forwarding(t *testing.T) {
	c := dnatForwardingConfig()
	c.Forwarding.Rules = nil
	s := forwardingState{}
	s.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
		return []byte(`{"nftables":[]}`), nil
	}
	s.externalExists = func(string) error { return nil }
	var paths []string
	s.readFile = func(path string) ([]byte, error) { paths = append(paths, path); return []byte("1"), nil }
	if err := s.apply(c); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/proc/sys/net/ipv4/ip_forward" {
		t.Fatal(paths)
	}
}
