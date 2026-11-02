package wglink

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

type forwardingFailureBackend struct{ fakeBackend }

func (b *forwardingFailureBackend) ApplyForwarding(*Config) error {
	return errors.New("boundary failure")
}
func TestForwardingFailureStopsBackend(t *testing.T) {
	b := &forwardingFailureBackend{}
	a := &Agent{Backend: b, Prepare: func(*Config) error { t.Fatal("prepare called before boundary success"); return nil }}
	if a.Reconcile(forwardingConfig()) == nil {
		t.Fatal("expected boundary failure")
	}
	if b.desired != nil {
		t.Fatal("interfaces applied before boundary success")
	}
	if status(a, "/readyz") != 503 {
		t.Fatal("premature readiness")
	}
}

func forwardingConfig() *Config {
	return &Config{Interfaces: []Interface{{Name: "wg-a"}, {Name: "wg-b"}}, Forwarding: &Forwarding{Enabled: true, Rules: []ForwardRule{{From: "wg-a", To: "wg-b", Source: "10.0.0.0/24", Destination: "10.1.0.0/24", Protocols: []string{"tcp"}, Ports: []int{443}}}}}
}
func TestForwardingValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ForwardRule)
	}{
		{"foreign", func(r *ForwardRule) { r.To = "eth0" }},
		{"injection", func(r *ForwardRule) { r.From = "wg-a\" accept" }},
		{"host bits", func(r *ForwardRule) { r.Source = "10.0.0.1/24" }},
		{"mixed family", func(r *ForwardRule) { r.Destination = "::/0" }},
		{"missing protocols", func(r *ForwardRule) { r.Protocols = nil }},
		{"unknown protocol", func(r *ForwardRule) { r.Protocols = []string{"all"} }},
		{"icmp ports", func(r *ForwardRule) { r.Protocols = []string{"icmp"} }},
		{"port zero", func(r *ForwardRule) { r.Ports = []int{0} }},
		{"port range", func(r *ForwardRule) { r.Ports = []int{65536} }},
		{"duplicate port", func(r *ForwardRule) { r.Ports = []int{443, 443} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := forwardingConfig()
			tc.mutate(&c.Forwarding.Rules[0])
			if validateForwarding(c) == nil {
				t.Fatal("accepted invalid rule")
			}
		})
	}
	if err := validateForwarding(forwardingConfig()); err != nil {
		t.Fatal(err)
	}
}
func TestForwardingRender(t *testing.T) {
	b := renderForwarding(forwardingConfig(), map[string]bool{"wg-a": true, "wg-b": true})
	for _, want := range []string{"policy accept", `comment "wg-link:v1"`, `iifname "wg-b" oifname "wg-a" ip saddr 10.1.0.0/24 ip daddr 10.0.0.0/24`, "tcp sport { 443 } ct state established", "ct state { new, established } counter accept", "ct state established counter accept", "iifname @owned_interfaces counter drop", "oifname @owned_interfaces counter drop"} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(b, "flush ruleset") || strings.Contains(b, "related") {
		t.Fatal("unbounded firewall operation")
	}
}
func TestForwardingOwnershipAndOrdering(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{true: "foreign", false: "owned"}[foreign], func(t *testing.T) {
			events := []string{}
			s := forwardingState{}
			s.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
				events = append(events, strings.Join(args, " "))
				if input != "" {
					events = append(events, "boundary")
					return nil, nil
				}
				if args[len(args)-1] == "tables" {
					if foreign {
						return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link"}}]}`), nil
					}
					return []byte(`{"nftables":[]}`), nil
				}
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link","comment":"foreign"}}]}`), nil
			}
			s.readFile = func(string) ([]byte, error) { events = append(events, "sysctl-read"); return []byte("0"), nil }
			s.writeFile = func(string, []byte, os.FileMode) error {
				events = append(events, "sysctl-write")
				return errors.New("read-only file system")
			}
			err := s.apply(forwardingConfig())
			if err == nil {
				t.Fatal("expected failure")
			}
			joined := strings.Join(events, ",")
			if foreign {
				if strings.Contains(joined, "boundary") || strings.Contains(joined, "sysctl") {
					t.Fatal(joined)
				}
			} else {
				if !strings.Contains(err.Error(), "securityContext.sysctls") {
					t.Fatal(err)
				}
				if strings.Index(joined, "boundary") > strings.Index(joined, "sysctl-read") {
					t.Fatal(joined)
				}
			}
		})
	}
}
func TestForwardingUnchangedAndDisable(t *testing.T) {
	s := forwardingState{}
	exists := false
	batches := []string{}
	writes := 0
	s.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
		if input != "" {
			exists = true
			batches = append(batches, input)
			return nil, nil
		}
		if args[len(args)-1] == "tables" {
			if exists {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link"}}]}`), nil
			}
			return []byte(`{"nftables":[]}`), nil
		}
		return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link","comment":"wg-link:v1"}},{"set":{"name":"owned_interfaces","elem":["wg-a","wg-b"]}}]}`), nil
	}
	s.readFile = func(string) ([]byte, error) { return []byte("1\n"), nil }
	s.writeFile = func(string, []byte, os.FileMode) error { writes++; return nil }
	c := forwardingConfig()
	for i := 0; i < 2; i++ {
		if err := s.apply(c); err != nil {
			t.Fatal(err)
		}
	}
	if len(batches) != 1 || writes != 0 {
		t.Fatalf("batches=%d writes=%d", len(batches), writes)
	}
	c.Forwarding = nil
	if err := s.apply(c); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || strings.Contains(batches[1], "ct state") {
		t.Fatal(batches)
	}
	if !strings.Contains(batches[1], "drop") {
		t.Fatal("lost deny boundary")
	}
}
