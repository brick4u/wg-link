//go:build linux

package wglink

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	haTable     = "wg_link_ha"
	haOwner     = "wg-link:ha:v1"
	haFreshness = 3 * time.Second
)

// HAGuard fences the configured WireGuard UDP ports in the current network
// namespace. Its nft table is independent of forwarding and is never removed
// by Close. Do not create a WireGuard interface before InstallClosed succeeds.
// Every mutation, including the nft acknowledgement, holds mu.
type HAGuard struct {
	mu        sync.Mutex
	ports     []int
	window    time.Duration
	run       nftRunner
	installed bool
	uncertain bool // A write may have reached the kernel without an acknowledgement.
	deadline  time.Time
}

// NewHAGuard creates a guard with a three-second kernel freshness window.
func NewHAGuard(ports []int) (*HAGuard, error) {
	return NewHAGuardWithTimeout(ports, haFreshness)
}

// NewHAGuardWithTimeout rejects duplicate/invalid ports and nonpositive
// timeouts. timeout is the maximum kernel-monotonic allowance per refresh.
func NewHAGuardWithTimeout(ports []int, timeout time.Duration) (*HAGuard, error) {
	if timeout < time.Millisecond || timeout > 10*time.Second {
		return nil, fmt.Errorf("HA guard timeout must be between 1ms and 10s")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("HA guard requires at least one UDP port")
	}
	seen := make(map[int]bool, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 || seen[p] {
			return nil, fmt.Errorf("invalid or duplicate HA UDP port %d", p)
		}
		seen[p] = true
	}
	copyPorts := append([]int(nil), ports...)
	sort.Ints(copyPorts)
	return &HAGuard{ports: copyPorts, window: timeout, run: runNFT}, nil
}

// InstallClosed atomically installs the default-deny boundary. A retained
// owned table is reused only when its managed ports match exactly; this avoids
// silently unguarding an old interface after a configuration change.
func (g *HAGuard) InstallClosed(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	// Always revalidate and write on startup, even if this process previously
	// observed a closed state: a retained namespace may contain old rules.
	g.uncertain = true
	if err := g.checkTable(ctx); err != nil {
		return err
	}
	if err := g.install(ctx, time.Time{}, 0); err != nil {
		return err
	}
	g.installed = true
	g.deadline = time.Time{}
	g.uncertain = false
	return nil
}

// AllowUntil opens only until the supplied absolute lease deadline, additionally
// bounded by a kernel monotonic timeout measured from refreshStarted (the
// current healthy observation/probe start). The caller computes the deadline
// from a confirmed lease RPC; this method never derives or extends it. The
// caller must obtain fresh health evidence before each refresh.
func (g *HAGuard) AllowUntil(ctx context.Context, absoluteDeadline, refreshStarted time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.installed {
		return fmt.Errorf("HA guard is not installed closed")
	}
	if absoluteDeadline.IsZero() || refreshStarted.IsZero() {
		return fmt.Errorf("HA guard requires deadline and refresh start")
	}
	now := time.Now()
	age := now.Sub(refreshStarted)
	if age < 0 || age >= g.window {
		return fmt.Errorf("HA refresh start is stale or in the future")
	}
	// nft meta time accepts integer Unix seconds. Truncate rather than round up:
	// the kernel must never allow packets beyond the caller's deadline.
	seconds := absoluteDeadline.Unix()
	if seconds <= now.Unix() || seconds < 0 {
		return fmt.Errorf("HA absolute deadline has expired or is subsecond")
	}
	ttl := min(g.window-age, time.Until(absoluteDeadline))
	milliseconds := ttl.Milliseconds()
	if milliseconds < 1 {
		return fmt.Errorf("HA monotonic timeout already expired")
	}
	// An error can mean the kernel accepted a transaction but its ACK was
	// lost. A later Close must never trust the previously cached deadline.
	g.uncertain = true
	if err := g.install(ctx, absoluteDeadline, milliseconds); err != nil {
		return err
	}
	g.deadline = absoluteDeadline
	g.uncertain = false
	return nil
}

// Close atomically returns to deny-only rules, keeping the table installed.
// A failed nft operation is reported; the caller must not assume it closed.
func (g *HAGuard) Close(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.installed {
		return fmt.Errorf("HA guard is not installed")
	}
	if g.deadline.IsZero() && !g.uncertain {
		return nil // Closed, acknowledged, and unchanged by this guard.
	}
	g.uncertain = true
	if err := g.install(ctx, time.Time{}, 0); err != nil {
		return err
	}
	g.deadline = time.Time{}
	g.uncertain = false
	return nil
}

// Deadline returns the deadline last successfully acknowledged by nft; a zero
// value indicates deny-only. This is not a substitute for checking nft errors.
func (g *HAGuard) Deadline() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.deadline
}

func (g *HAGuard) checkTable(ctx context.Context) error {
	out, err := g.run(ctx, "", "-j", "list", "tables")
	if err != nil {
		return fmt.Errorf("list nft tables: %w", err)
	}
	var tables struct {
		NFTables []struct {
			Table *struct{ Family, Name string }
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &tables); err != nil {
		return fmt.Errorf("decode nft tables: %w", err)
	}
	exists := false
	for _, entry := range tables.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == haTable {
			exists = true
		}
	}
	if !exists {
		return nil
	}
	out, err = g.run(ctx, "", "-j", "list", "table", "inet", haTable)
	if err != nil {
		return fmt.Errorf("inspect HA table: %w", err)
	}
	var table struct {
		NFTables []struct {
			Table *struct{ Family, Name, Comment string }
			Set   *struct {
				Name string
				Elem []json.RawMessage
			}
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &table); err != nil {
		return fmt.Errorf("decode HA table: %w", err)
	}
	owned, found := false, false
	var ports []int
	for _, entry := range table.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == haTable && entry.Table.Comment == haOwner {
			owned = true
		}
		if entry.Set != nil && entry.Set.Name == "managed_ports" {
			found = true
			for _, raw := range entry.Set.Elem {
				var p int
				if err := json.Unmarshal(raw, &p); err != nil {
					return fmt.Errorf("invalid managed HA port: %w", err)
				}
				ports = append(ports, p)
			}
		}
	}
	sort.Ints(ports)
	if !owned || !found || len(ports) != len(g.ports) {
		return fmt.Errorf("refusing foreign or differently configured nft table inet %s", haTable)
	}
	for i, p := range ports {
		if p != g.ports[i] {
			return fmt.Errorf("refusing changed HA UDP ports while nft table persists")
		}
	}
	return nil
}

func (g *HAGuard) install(ctx context.Context, deadline time.Time, milliseconds int64) error {
	// One nft -f transaction replaces the entire owned table; packet processing
	// never observes a partial update. No global ruleset or other table changes.
	var b strings.Builder
	// A fresh table has no delete target. Listing is required; never infer an
	// absent table from a failed lookup.
	out, err := g.run(ctx, "", "-j", "list", "tables")
	if err != nil {
		return fmt.Errorf("list nft tables before HA update: %w", err)
	}
	var tables struct {
		NFTables []struct {
			Table *struct{ Family, Name string }
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &tables); err != nil {
		return fmt.Errorf("decode nft tables before HA update: %w", err)
	}
	for _, entry := range tables.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == haTable {
			if err := g.checkTable(ctx); err != nil {
				return err
			}
			b.WriteString("delete table inet " + haTable + "\n")
			break
		}
	}
	fmt.Fprintf(&b, "add table inet %s { comment %q; }\n", haTable, haOwner)
	portStrings := make([]string, len(g.ports))
	for i, p := range g.ports {
		portStrings[i] = strconv.Itoa(p)
	}
	fmt.Fprintf(&b, "add set inet %s managed_ports { type inet_service; elements = { %s }; }\n", haTable, strings.Join(portStrings, ", "))
	if milliseconds > 0 {
		entries := make([]string, len(g.ports))
		for i, p := range portStrings {
			entries[i] = fmt.Sprintf("%s timeout %dms", p, milliseconds)
		}
		fmt.Fprintf(&b, "add set inet %s active_ports { type inet_service; flags timeout; elements = { %s }; }\n", haTable, strings.Join(entries, ", "))
	}
	for _, chain := range []struct{ name, port string }{{"input", "dport"}, {"output", "sport"}} {
		fmt.Fprintf(&b, "add chain inet %s %s { type filter hook %s priority -310; policy accept; }\n", haTable, chain.name, chain.name)
		if milliseconds > 0 {
			fmt.Fprintf(&b, "add rule inet %s %s udp %s @active_ports meta time < %d accept\n", haTable, chain.name, chain.port, deadline.Unix())
		}
		fmt.Fprintf(&b, "add rule inet %s %s udp %s @managed_ports drop\n", haTable, chain.name, chain.port)
	}
	if _, err := g.run(ctx, b.String(), "-f", "-"); err != nil {
		return fmt.Errorf("install HA nft transaction: %w", err)
	}
	return nil
}
