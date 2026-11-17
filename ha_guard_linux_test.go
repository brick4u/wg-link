//go:build linux

package wglink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHAGuardValidatePorts(t *testing.T) {
	for _, timeout := range []time.Duration{-time.Second, 0, time.Microsecond, 11 * time.Second} {
		if _, err := NewHAGuardWithTimeout([]int{51820}, timeout); err == nil {
			t.Fatalf("accepted invalid timeout %s", timeout)
		}
	}
	custom, err := NewHAGuardWithTimeout([]int{51820}, 2*time.Second)
	if err != nil || custom.window != 2*time.Second {
		t.Fatalf("custom timeout: %v, %v", custom, err)
	}
	for _, ports := range [][]int{nil, {}, {0}, {65536}, {-1}, {51820, 51820}} {
		if _, err := NewHAGuard(ports); err == nil {
			t.Fatalf("accepted invalid ports %v", ports)
		}
	}
	g, err := NewHAGuard([]int{51821, 51820})
	if err != nil || fmt.Sprint(g.ports) != "[51820 51821]" {
		t.Fatalf("ports %v, error %v", g.ports, err)
	}
}

func TestHAGuardClosedOpenClose(t *testing.T) {
	g, _ := NewHAGuard([]int{51820, 51821})
	var batches []string
	exists := false
	g.run = func(_ context.Context, input string, args ...string) ([]byte, error) {
		if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
			if exists {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha"}}]}`), nil
			}
			return []byte(`{"nftables":[]}`), nil
		}
		if fmt.Sprint(args) == "[-j list table inet wg_link_ha]" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha","comment":"wg-link:ha:v1"}},{"set":{"name":"managed_ports","elem":[51820,51821]}}]}`), nil
		}
		if fmt.Sprint(args) != "[-f -]" {
			t.Fatalf("unexpected nft args: %v", args)
		}
		batches = append(batches, input)
		exists = true
		return nil, nil
	}
	ctx := context.Background()
	if err := g.AllowUntil(ctx, time.Now().Add(10*time.Second), time.Now()); err == nil {
		t.Fatal("allowed before closed install")
	}
	if err := g.InstallClosed(ctx); err != nil {
		t.Fatal(err)
	}
	closed := batches[0]
	for _, fragment := range []string{"add table inet wg_link_ha", `comment "wg-link:ha:v1"`, "udp dport @managed_ports drop", "udp sport @managed_ports drop", "priority -310", "51820, 51821"} {
		if !strings.Contains(closed, fragment) {
			t.Errorf("closed batch lacks %q: %s", fragment, closed)
		}
	}
	if strings.Contains(closed, "active_ports") || strings.Contains(closed, "delete table") || !g.Deadline().IsZero() {
		t.Fatal("initial install was not closed")
	}
	d := time.Now().Add(10 * time.Second)
	if err := g.AllowUntil(ctx, d, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	open := batches[1]
	for _, fragment := range []string{"delete table inet wg_link_ha", "flags timeout", "timeout 1", "udp dport @active_ports meta time <", "udp sport @active_ports meta time <", fmt.Sprintf("meta time < %d", d.Unix())} {
		if !strings.Contains(open, fragment) {
			t.Errorf("open batch lacks %q: %s", fragment, open)
		}
	}
	if !g.Deadline().Equal(d) {
		t.Fatal("deadline not recorded on acknowledged update")
	}
	if err := g.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(batches[2], "active_ports") || !g.Deadline().IsZero() {
		t.Fatal("close retained an allowance")
	}
}

func TestHAGuardRefusesForeignOrChangedTable(t *testing.T) {
	for _, table := range []string{
		`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha","comment":"other"}},{"set":{"name":"managed_ports","elem":[51820]}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha","comment":"wg-link:ha:v1"}},{"set":{"name":"managed_ports","elem":[51821]}}]}`,
	} {
		g, _ := NewHAGuard([]int{51820})
		g.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if fmt.Sprint(args) == "[-j list tables]" {
				return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha"}}]}`), nil
			}
			if fmt.Sprint(args) == "[-j list table inet wg_link_ha]" {
				return []byte(table), nil
			}
			t.Fatal("must not modify foreign table")
			return nil, nil
		}
		if err := g.InstallClosed(context.Background()); err == nil {
			t.Fatalf("accepted foreign table %s", table)
		}
	}
}

func TestHAGuardRejectsStaleAndExpired(t *testing.T) {
	g, _ := NewHAGuard([]int{51820})
	g.installed = true
	g.run = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("invalid allow must not execute nft")
		return nil, nil
	}
	for _, tc := range []struct{ deadline, start time.Time }{
		{time.Time{}, time.Now()},
		{time.Now().Add(time.Second), time.Time{}},
		{time.Now().Add(time.Second), time.Now().Add(-4 * time.Second)},
		{time.Now().Add(time.Second), time.Now().Add(time.Second)},
		{time.Now().Add(-time.Second), time.Now()},
	} {
		if err := g.AllowUntil(context.Background(), tc.deadline, tc.start); err == nil {
			t.Fatalf("accepted invalid allow: %+v", tc)
		}
	}
}

func TestHAGuardNftFailureKeepsAcknowledgedState(t *testing.T) {
	g, _ := NewHAGuard([]int{51820})
	g.installed = true
	d := time.Now().Add(10 * time.Second)
	g.deadline = d
	g.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if fmt.Sprint(args) == "[-j list table inet wg_link_ha]" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha","comment":"wg-link:ha:v1"}},{"set":{"name":"managed_ports","elem":[51820]}}]}`), nil
		}
		if len(args) > 0 && args[0] == "-j" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha"}}]}`), nil
		}
		return nil, errors.New("nft rejected")
	}
	if err := g.Close(context.Background()); err == nil || !g.Deadline().Equal(d) {
		t.Fatal("failed close incorrectly reported success")
	}
}

func TestHAGuardConcurrentUpdatesSerialize(t *testing.T) {
	g, _ := NewHAGuard([]int{51820})
	g.installed = true
	var wg sync.WaitGroup
	active := make(chan struct{}, 1)
	g.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		select {
		case active <- struct{}{}:
		default:
			t.Error("nft commands overlapped")
		}
		defer func() { <-active }()
		if fmt.Sprint(args) == "[-j list table inet wg_link_ha]" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha","comment":"wg-link:ha:v1"}},{"set":{"name":"managed_ports","elem":[51820]}}]}`), nil
		}
		if len(args) > 0 && args[0] == "-j" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"wg_link_ha"}}]}`), nil
		}
		return nil, nil
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
