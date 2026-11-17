package wglink

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestActivationConfigOptInAndDefaults(t *testing.T) {
	c := loadedConfig(t)
	if c.Activation != nil {
		t.Fatal("default unexpectedly activates election")
	}
	c.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "gateway-active", RequireReadyContainers: []string{"application"}}}
	c.Interfaces[0].ListenPort = 51820
	if err := validateActivation(c); err != nil {
		t.Fatal(err)
	}
	if c.Activation.KubernetesLease.LeaseDuration != 15*time.Second || c.Activation.KubernetesLease.RenewDeadline != 10*time.Second || c.Activation.FenceTimeout != 3*time.Second {
		t.Fatal("incorrect defaults")
	}
}

func TestActivationConfigRejectsUnsafePortsAndDurations(t *testing.T) {
	for _, port := range []int{0, -1, 500, 4500, 65536} {
		c := loadedConfig(t)
		c.Interfaces[0].ListenPort = port
		c.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "active"}}
		if validateActivation(c) == nil {
			t.Fatalf("accepted unsafe port %d", port)
		}
	}
	c := loadedConfig(t)
	c.Interfaces[0].ListenPort = 51820
	c.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "active", LeaseDuration: 12 * time.Second}}
	if validateActivation(c) == nil {
		t.Fatal("accepted overlapping authorization budget")
	}
	c.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "active", RequireReadyContainers: []string{"app", "app"}}}
	if validateActivation(c) == nil {
		t.Fatal("accepted duplicate ready condition")
	}
}

type fakeActivation struct {
	selected, configured, ready bool
	closed                      int
	failed                      int
}

func (f *fakeActivation) ConfigurationFailed() { f.failed++; f.selected = false; f.configured = false }
func (f *fakeActivation) Selected() bool       { return f.selected }
func (f *fakeActivation) Ready() bool          { return f.ready && f.configured && f.selected }
func (f *fakeActivation) SetConfigured(v bool) { f.configured = v }
func (f *fakeActivation) ReconcileGuard(context.Context) error {
	if !f.Selected() || !f.configured {
		f.closed++
	}
	return nil
}

type standbyBackend struct {
	fakeBackend
	prepared int
}

func (b *standbyBackend) PrepareStandby(c *Config) error { b.prepared++; return b.Apply(nil) }
func TestActivationStandbyAndActiveReadiness(t *testing.T) {
	c := loadedConfig(t)
	c.Interfaces[0].ListenPort = 51820
	c.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "active"}}
	b := &standbyBackend{}
	gate := &fakeActivation{}
	a := &Agent{Backend: b, Activation: gate}
	if err := a.Reconcile(c); err != nil {
		t.Fatal(err)
	}
	if b.prepared != 1 || len(b.desired) != 0 || status(a, "/readyz") != 503 || gate.closed == 0 {
		t.Fatal("standby not fenced")
	}
	gate.selected = true
	gate.ready = true
	if err := a.Reconcile(c); err != nil {
		t.Fatal(err)
	}
	if len(b.desired) != 1 || status(a, "/readyz") != 200 {
		t.Fatal("healthy holder not configured")
	}
	gate.selected = false
	if status(a, "/readyz") != 503 {
		t.Fatal("stale local-ready ignored activation loss")
	}
	if err := a.Reconcile(c); err != nil {
		t.Fatal(err)
	}
	if len(b.desired) != 0 {
		t.Fatal("standby retained managed interfaces")
	}
}
func TestActivationPortReloadRejectedBeforeBackendMutation(t *testing.T) {
	initial := loadedConfig(t)
	initial.Interfaces[0].ListenPort = 51820
	initial.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "active"}}
	next := *initial
	next.Interfaces = append([]Interface(nil), initial.Interfaces...)
	next.Interfaces[0].ListenPort = 51999
	gate := &fakeActivation{selected: true, configured: true, ready: true}
	b := &standbyBackend{}
	a := &Agent{Backend: b, Activation: gate, ValidateRuntime: func(c *Config) error { return ValidateActivationReload(initial, c) }}
	if a.Reconcile(&next) == nil {
		t.Fatal("accepted unguarded hot-reload port")
	}
	if len(b.desired) != 0 || b.prepared != 0 || gate.configured {
		t.Fatal("mutation occurred before restart-required validation")
	}
	if ValidateActivationReload(initial, initial) != nil {
		t.Fatal("identical config rejected")
	}
}

func TestSelectedBackendFailureYieldsActivation(t *testing.T) {
	c := loadedConfig(t)
	c.Activation = &ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "active"}}
	gate := &fakeActivation{selected: true, ready: true}
	b := &standbyBackend{fakeBackend: fakeBackend{err: errors.New("kernel apply failure")}}
	a := &Agent{Backend: b, Activation: gate}
	if a.Reconcile(c) == nil || gate.failed != 1 || gate.selected || gate.configured || status(a, "/readyz") != 503 {
		t.Fatal("broken holder retained authority")
	}
}

func TestActivationCannotSilentlyLoseConfiguration(t *testing.T) {
	c := loadedConfig(t)
	gate := &fakeActivation{selected: true, configured: true, ready: true}
	b := &standbyBackend{}
	a := &Agent{Backend: b, Activation: gate}
	if a.Reconcile(c) == nil || gate.configured || status(a, "/readyz") != 503 {
		t.Fatal("HA disable was not fail-closed")
	}
}
