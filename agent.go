package wglink

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Resolver interface {
	Resolve(ServiceRef) (*net.UDPAddr, string)
}
type Agent struct {
	Backend     Backend
	Discovery   Resolver
	Prepare     func(*Config) error
	mu          sync.Mutex
	ready       bool
	failures    uint64
	successes   uint64
	lastSuccess time.Time
	states      map[string]int
	// Only changes in declared discovery/static endpoint overwrite authenticated roaming.
	endpoints map[string]string
}

func (a *Agent) Reconcile(c *Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var prepareErr error
	if a.Prepare != nil {
		prepareErr = a.Prepare(c)
	}
	// Discovery credential errors must not prevent local fail-closed routes.
	desired := []DesiredInterface{}
	next := map[string]string{}
	states := map[string]int{}
	for _, n := range c.Interfaces {
		d := DesiredInterface{Interface: n}
		for _, p := range n.Peers {
			pc := wgtypes.PeerConfig{PublicKey: p.key, PresharedKey: &p.psk, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: keepalive(p.PersistentKeepalive)}
			for _, cidr := range p.AllowedIPs {
				_, v, _ := net.ParseCIDR(cidr)
				pc.AllowedIPs = append(pc.AllowedIPs, *v)
			}
			var endpoint *net.UDPAddr
			state := "learned"
			if p.Service != nil {
				state = "missing"
				if a.Discovery != nil {
					endpoint, state = a.Discovery.Resolve(*p.Service)
				}
			} else if p.Endpoint != "" {
				endpoint, _ = parseEndpoint(p.Endpoint)
				state = "static"
			}
			states[state]++
			id := n.Name + "/" + p.PublicKey
			if endpoint != nil {
				next[id] = endpoint.String()
				if a.endpoints[id] != next[id] {
					pc.Endpoint = endpoint
				}
			} else {
				next[id] = a.endpoints[id]
			}
			// Missing discovery leaves last authenticated endpoint, but protected routes never fall back to default.
			d.Peers = append(d.Peers, DesiredPeer{Config: pc, Endpoint: endpoint})
		}
		desired = append(desired, d)
	}
	if e := a.Backend.Apply(desired); e != nil {
		a.failures++
		a.ready = false
		return e
	}
	a.endpoints = next
	a.states = states
	if prepareErr != nil {
		a.ready = false
		a.failures++
		return prepareErr
	}
	a.ready = true
	a.successes++
	a.lastSuccess = time.Now()
	return nil
}
func (a *Agent) ReloadFailure() { a.mu.Lock(); defer a.mu.Unlock(); a.failures++; a.ready = false }
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if !a.ready {
			http.Error(w, "not ready", 503)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "wg_link_reconcile_errors_total %d\nwg_link_reconcile_success_total %d\nwg_link_last_success_timestamp_seconds %d\n", a.failures, a.successes, a.lastSuccess.Unix())
		for _, state := range []string{"ready", "missing", "ambiguous", "static", "learned"} {
			fmt.Fprintf(w, "wg_link_endpoints{state=%q} %d\n", state, a.states[state])
		}
		if d, ok := a.Discovery.(*Discovery); ok {
			fmt.Fprintf(w, "wg_link_watch_errors_total %d\n", d.Errors.Load())
			degraded := 0
			if d.Degraded() {
				degraded = 1
			}
			fmt.Fprintf(w, "wg_link_discovery_degraded %d\n", degraded)
		}
		devices, e := a.Backend.Devices()
		if e != nil {
			fmt.Fprintln(w, "wg_link_device_scrape_error 1")
			return
		}
		for _, d := range devices {
			if d.Name == "" {
				continue
			}
			for i, p := range d.Peers {
				age := -1.0
				if !p.LastHandshakeTime.IsZero() {
					age = time.Since(p.LastHandshakeTime).Seconds()
				}
				fmt.Fprintf(w, "wg_link_handshake_age_seconds{interface=%q,peer=%q} %g\nwg_link_receive_bytes_total{interface=%q,peer=%q} %d\nwg_link_transmit_bytes_total{interface=%q,peer=%q} %d\n", d.Name, fmt.Sprint(i), age, d.Name, fmt.Sprint(i), p.ReceiveBytes, d.Name, fmt.Sprint(i), p.TransmitBytes)
			}
		}
	})
	return mux
}

// Run reloads complete snapshots every second, reopening paths so projected volume swaps work.
// Errors retain the previous kernel configuration and never log secret material.
func (a *Agent) Run(ctx context.Context, path string, events <-chan struct{}, onError func(error)) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		c, e := Load(path)
		if e == nil {
			e = a.Reconcile(c)
		} else {
			a.ReloadFailure()
		}
		if e != nil && onError != nil {
			onError(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-events:
		}
	}
}
