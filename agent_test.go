package wglink

import (
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestCredentialFailureStillProtectsRoutes(t *testing.T) {
	b := &fakeBackend{}
	a := &Agent{Backend: b, Prepare: func(*Config) error { return errors.New("credentials unavailable") }}
	c := loadedConfig(t)
	c.Interfaces[0].Peers[0].Service = &ServiceRef{"ns", "peer", "wg"}
	if a.Reconcile(c) == nil {
		t.Fatal("expected discovery setup failure")
	}
	if len(b.desired) != 1 || len(b.desired[0].Interface.Routes) != 1 {
		t.Fatal("credential error skipped fail-closed local configuration")
	}
	if status(a, "/readyz") != 503 {
		t.Fatal("credential error should be visible")
	}
}

type fakeBackend struct {
	desired []DesiredInterface
	err     error
}

func (f *fakeBackend) Apply(d []DesiredInterface) error    { f.desired = d; return f.err }
func (f *fakeBackend) Devices() ([]*wgtypes.Device, error) { return nil, nil }

type fakeResolver struct {
	endpoint string
	state    string
}

func (f *fakeResolver) Resolve(ServiceRef) (*net.UDPAddr, string) {
	if f.endpoint == "" {
		return nil, f.state
	}
	e, _ := parseEndpoint(f.endpoint)
	return e, f.state
}
func loadedConfig(t *testing.T) *Config {
	t.Helper()
	path, data := fixture(t)
	if e := os.WriteFile(path, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func status(a *Agent, path string) int {
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w.Code
}
func TestBootstrapNoEndpointOrHandshake(t *testing.T) {
	b := &fakeBackend{}
	a := &Agent{Backend: b}
	c := loadedConfig(t)
	c.Interfaces[0].Peers = nil
	if status(a, "/readyz") != 503 {
		t.Fatal("premature readiness")
	}
	if e := a.Reconcile(c); e != nil {
		t.Fatal(e)
	}
	if status(a, "/readyz") != 200 {
		t.Fatal("readiness depends on peer")
	}
	if len(b.desired[0].Interface.Routes) != 1 {
		t.Fatal("route removed when peer absent")
	}
	b.err = errors.New("kernel")
	if a.Reconcile(c) == nil || status(a, "/readyz") != 503 || status(a, "/healthz") != 200 {
		t.Fatal("health semantics")
	}
}
func TestEndpointChangesAndRoaming(t *testing.T) {
	b := &fakeBackend{}
	r := &fakeResolver{"10.0.0.2:51820", "ready"}
	a := &Agent{Backend: b, Discovery: r}
	c := loadedConfig(t)
	c.Interfaces[0].Peers[0].Service = &ServiceRef{"ns", "peer", "wg"}
	for i := 0; i < 2; i++ {
		if e := a.Reconcile(c); e != nil {
			t.Fatal(e)
		}
		p := b.desired[0].Peers[0]
		if (p.Config.Endpoint != nil) != (i == 0) {
			t.Fatal("unchanged endpoint overwrites roaming")
		}
		if p.Endpoint == nil {
			t.Fatal("missing recreated-peer fallback")
		}
	}
	r.endpoint = "10.0.0.3:51820"
	if e := a.Reconcile(c); e != nil {
		t.Fatal(e)
	}
	if b.desired[0].Peers[0].Config.Endpoint.String() != r.endpoint {
		t.Fatal("endpoint not updated")
	}
	r.endpoint = ""
	r.state = "ambiguous"
	if e := a.Reconcile(c); e != nil {
		t.Fatal(e)
	}
	if b.desired[0].Peers[0].Config.Endpoint != nil || len(b.desired[0].Interface.Routes) != 1 || a.states["ambiguous"] != 1 {
		t.Fatal("missing endpoint must retain protected routes and authenticated state")
	}
}
func TestFailedApplyRetriesEndpoint(t *testing.T) {
	b := &fakeBackend{err: errors.New("kernel")}
	a := &Agent{Backend: b}
	c := loadedConfig(t)
	c.Interfaces[0].Peers[0].Endpoint = "10.0.0.2:51820"
	if a.Reconcile(c) == nil {
		t.Fatal("expected error")
	}
	b.err = nil
	if e := a.Reconcile(c); e != nil {
		t.Fatal(e)
	}
	if b.desired[0].Peers[0].Config.Endpoint == nil {
		t.Fatal("failed apply committed endpoint cache")
	}
}
func TestGuardRoutes(t *testing.T) {
	for _, prefix := range []string{"10.1.0.0/16", "2001:db8::/64", "0.0.0.0/0", "::/0"} {
		guard := routeFor(prefix, true, 123)
		active := routeFor(prefix, false, 123)
		if guard.LinkIndex != 0 || guard.Priority <= active.Priority || guard.Type != 6 || guard.Dst.String() != prefix || active.LinkIndex != 123 {
			t.Fatalf("unsafe route pair %v %v", guard, active)
		}
	}
}
