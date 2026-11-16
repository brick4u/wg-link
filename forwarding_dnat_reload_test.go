package wglink

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Reload failures must deactivate already-committed NAT, not just avoid adding
// NAT to a fresh namespace. The fake runner models atomic table replacement.
func TestDNATReloadFailureDeactivatesCommittedNAT(t *testing.T) {
	for _, failure := range []string{"backend", "commit", "sysctl"} {
		t.Run(failure, func(t *testing.T) {
			b := &stagedForwardingBackend{}
			var installed string
			fail := false
			b.state.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
				if input != "" {
					if fail && failure == "commit" && strings.Contains(input, "counter dnat") {
						return nil, errors.New("atomic nft failure")
					}
					installed = input
					return nil, nil
				}
				if args[len(args)-1] == "tables" {
					if installed == "" {
						return []byte(`{"nftables":[]}`), nil
					}
					return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link"}}]}`), nil
				}
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link","comment":"wg-link:v1"}},{"set":{"name":"owned_interfaces","elem":["eth0","wg-a","wg-b","wg-historical"]}}]}`), nil
			}
			b.state.externalExists = func(string) error { return nil }
			b.state.readFile = func(string) ([]byte, error) {
				if fail && failure == "sysctl" {
					return nil, errors.New("read failed")
				}
				return []byte("1"), nil
			}
			a := &Agent{Backend: b}
			c := dnatForwardingConfig()
			if err := a.Reconcile(c); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(installed, "counter dnat") {
				t.Fatal("initial NAT not committed", installed)
			}
			fail = true
			if failure == "backend" {
				b.err = errors.New("route failure")
			}
			c.Forwarding.DNAT[0].Port = 12102
			if err := a.Reconcile(c); err == nil {
				t.Fatal("expected reload failure")
			}
			if !strings.HasPrefix(installed, "delete table inet wg_link\n") || strings.Contains(installed, "type nat") || strings.Contains(installed, "ct state") || !strings.Contains(installed, `"wg-historical"`) {
				t.Fatal("reload failure did not deactivate NAT and retain historical scoped denial", installed)
			}
		})
	}
}
