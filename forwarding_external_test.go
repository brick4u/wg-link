package wglink

import (
	"context"
	"errors"
	"github.com/vishvananda/netlink"
	"os"
	"reflect"
	"strings"
	"testing"
)

func externalForwardingConfig() *Config {
	c := forwardingConfig()
	c.Forwarding.ExternalInterfaces = []string{"eth0"}
	c.Forwarding.Rules = []ForwardRule{{From: "eth0", To: "eth0", Source: "198.18.10.0/24", Destination: "203.0.113.0/24", Protocols: []string{"tcp"}}}
	c.Forwarding.Masquerade = []MasqueradeRule{{From: "eth0", To: "eth0", Source: "198.18.10.0/24", Destination: "203.0.113.0/24"}}
	return c
}

func TestExternalForwardingValidation(t *testing.T) {
	if err := validateForwarding(externalForwardingConfig()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"duplicate":           func(c *Config) { c.Forwarding.ExternalInterfaces = []string{"eth0", "eth0"} },
		"owned collision":     func(c *Config) { c.Forwarding.ExternalInterfaces = []string{"wg-a"} },
		"dot":                 func(c *Config) { c.Forwarding.ExternalInterfaces = []string{"."} },
		"dotdot":              func(c *Config) { c.Forwarding.ExternalInterfaces = []string{".."} },
		"invalid name":        func(c *Config) { c.Forwarding.ExternalInterfaces = []string{"eth0;accept"} },
		"undeclared":          func(c *Config) { c.Forwarding.Masquerade[0].To = "eth1" },
		"missing source":      func(c *Config) { c.Forwarding.Masquerade[0].Source = "" },
		"missing destination": func(c *Config) { c.Forwarding.Masquerade[0].Destination = "" },
		"host bits":           func(c *Config) { c.Forwarding.Masquerade[0].Source = "198.18.10.1/24" },
		"ipv6": func(c *Config) {
			c.Forwarding.Masquerade[0].Source = "2001:db8::/64"
			c.Forwarding.Masquerade[0].Destination = "2001:db8:1::/64"
		},
		"disabled nat": func(c *Config) { c.Forwarding.Enabled = false; c.Forwarding.Rules = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := externalForwardingConfig()
			mutate(c)
			if validateForwarding(c) == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestExternalNATRender(t *testing.T) {
	c := externalForwardingConfig()
	batch := renderForwarding(c, map[string]bool{"eth0": true, "wg-a": true})
	for _, want := range []string{"type nat hook postrouting priority srcnat", `postrouting iifname "eth0" oifname "eth0" ip saddr 198.18.10.0/24 ip daddr 203.0.113.0/24 counter masquerade`, `forward iifname "eth0" oifname "eth0" ip saddr 203.0.113.0/24 ip daddr 198.18.10.0/24 meta l4proto tcp ct state established`} {
		if !strings.Contains(batch, want) {
			t.Fatalf("missing %s in %s", want, batch)
		}
	}
	c.Forwarding = nil
	if b := renderForwarding(c, map[string]bool{"eth0": true}); strings.Contains(b, "masquerade") || strings.Contains(b, "postrouting") || !strings.Contains(b, `"eth0"`) {
		t.Fatal(b)
	}
}

func TestExternalNATStagingFailures(t *testing.T) {
	for _, failure := range []string{"missing link", "backend", "commit", "link disappears", "sysctl"} {
		t.Run(failure, func(t *testing.T) {
			b := &stagedForwardingBackend{}
			batches := []string{}
			b.state.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
				if input != "" {
					if strings.Contains(input, "masquerade") && failure == "commit" {
						return nil, errors.New("atomic nft failure")
					}
					batches = append(batches, input)
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
			a := &Agent{Backend: b}
			if a.Reconcile(externalForwardingConfig()) == nil {
				t.Fatal("expected failure")
			}
			if len(batches) != 1 || strings.Contains(batches[0], "masquerade") || strings.Contains(batches[0], "ct state") || !strings.Contains(batches[0], `"eth0"`) {
				t.Fatalf("failure did not retain scoped deny: %v", batches)
			}
		})
	}
}

func TestExternalDenySurvivesRestart(t *testing.T) {
	s := forwardingState{}
	var installed string
	s.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
		if input != "" {
			installed = input
			return nil, nil
		}
		if args[len(args)-1] == "tables" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link"}}]}`), nil
		}
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link","comment":"wg-link:v1"}},{"set":{"name":"owned_interfaces","elem":["eth0","wg-old"]}}]}`), nil
	}
	if err := s.apply(&Config{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"eth0"`, `"wg-old"`, "counter drop"} {
		if !strings.Contains(installed, want) {
			t.Fatal(installed)
		}
	}
	if strings.Contains(installed, "masquerade") || strings.Contains(installed, "flush ruleset") {
		t.Fatal(installed)
	}
}

func TestExternalForeignLinkPreservation(t *testing.T) {
	c := externalForwardingConfig()
	external := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Alias: "foreign-owner", MTU: 1400, Index: 42}}
	before := *external
	foreign := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "unrelated", MTU: 1500}}
	stale := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg-stale", Alias: ownerAlias}}
	scoped, err := scopeForwardingLinks(c, []netlink.Link{external, foreign, stale})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*external, before) {
		t.Fatal("external link mutated")
	}
	if len(c.Interfaces) != 2 || len(scoped.Interfaces) != 3 || scoped.Interfaces[2].Name != "wg-stale" {
		t.Fatalf("unexpected declared scope: %+v", scoped.Interfaces)
	}
	for _, n := range scoped.Interfaces {
		if n.Name == "eth0" || n.Name == "unrelated" {
			t.Fatal("foreign link entered backend management scope")
		}
	}
	external.Alias = ownerAlias
	if _, err := scopeForwardingLinks(c, []netlink.Link{external}); err == nil {
		t.Fatal("accepted external ownership conflict")
	}
	external.Alias = ""
	c.Forwarding.ExternalInterfaces = nil
	c.Interfaces = append(c.Interfaces, Interface{Name: "eth0"})
	if _, err := scopeForwardingLinks(c, []netlink.Link{external}); err == nil {
		t.Fatal("accepted foreign declared WireGuard link")
	}
}
