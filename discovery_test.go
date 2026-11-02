package wglink

import (
	"context"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func ptr[T any](v T) *T { return &v }
func TestInformerLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service, slice := serviceFixture()
	client := fake.NewClientset(service, slice)
	events := make(chan struct{}, 100)
	notify := func() {
		select {
		case events <- struct{}{}:
		default:
		}
	}
	d := NewDiscovery(ctx, client, []string{"ns"}, notify)
	if !cache.WaitForCacheSync(ctx.Done(), d.Synced) {
		t.Fatal("cache did not sync")
	}
	ref := ServiceRef{"ns", "peer", "wg"}
	await := func(state, address string) {
		t.Helper()
		for {
			e, s := d.Resolve(ref)
			if s == state && (address == "" || (e != nil && e.String() == address)) {
				return
			}
			select {
			case <-events:
			case <-ctx.Done():
				t.Fatalf("state=%s endpoint=%v expected=%s %s", s, e, state, address)
			}
		}
	}
	await("ready", "10.0.0.2:51820")
	slice.Endpoints[0].Addresses = []string{"10.0.0.3"}
	if _, e := client.DiscoveryV1().EndpointSlices("ns").Update(ctx, slice, meta.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	await("ready", "10.0.0.3:51820")
	if e := client.CoreV1().Services("ns").Delete(ctx, "peer", meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	await("missing", "")
	service.UID = "recreated"
	if _, e := client.CoreV1().Services("ns").Create(ctx, service, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	await("missing", "")
	slice.OwnerReferences[0].UID = service.UID
	if _, e := client.DiscoveryV1().EndpointSlices("ns").Update(ctx, slice, meta.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	await("ready", "10.0.0.3:51820")
	d.EnsureNamespaces([]string{"another"})
	if !cache.WaitForCacheSync(ctx.Done(), d.Synced) {
		t.Fatal("new namespace did not sync")
	}
}

func serviceFixture() (*core.Service, *discovery.EndpointSlice) {
	s := &core.Service{ObjectMeta: meta.ObjectMeta{Name: "peer", Namespace: "ns", UID: types.UID("new")}, Spec: core.ServiceSpec{Ports: []core.ServicePort{{Name: "wg", Protocol: core.ProtocolUDP, Port: 51820}}}}
	slice := &discovery.EndpointSlice{ObjectMeta: meta.ObjectMeta{Name: "slice", Namespace: "ns", Labels: map[string]string{discovery.LabelServiceName: "peer"}, OwnerReferences: []meta.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "peer", UID: s.UID}}}, AddressType: discovery.AddressTypeIPv4, Ports: []discovery.EndpointPort{{Name: ptr("wg"), Protocol: ptr(core.ProtocolUDP), Port: ptr(int32(51820))}}, Endpoints: []discovery.Endpoint{{Addresses: []string{"10.0.0.2"}, Conditions: discovery.EndpointConditions{Ready: ptr(true)}}}}
	return s, slice
}
func TestSelectEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*core.Service, *discovery.EndpointSlice) []*discovery.EndpointSlice
		state  string
	}{
		{"ready", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			return []*discovery.EndpointSlice{s}
		}, "ready"},
		{"old UID", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.OwnerReferences[0].UID = "old"
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"unowned", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.OwnerReferences = nil
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"unknown readiness", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.Endpoints[0].Conditions.Ready = nil
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"not ready", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.Endpoints[0].Conditions.Ready = ptr(false)
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"terminating", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.Endpoints[0].Conditions.Terminating = ptr(true)
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"ambiguous addresses", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.Endpoints[0].Addresses = append(s.Endpoints[0].Addresses, "10.0.0.3")
			return []*discovery.EndpointSlice{s}
		}, "ambiguous"},
		{"ambiguous slices", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			other := s.DeepCopy()
			other.Endpoints[0].Addresses = []string{"10.0.0.3"}
			return []*discovery.EndpointSlice{s, other}
		}, "ambiguous"},
		{"duplicate slice addresses", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			return []*discovery.EndpointSlice{s, s.DeepCopy()}
		}, "ready"},
		{"recreated service", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			old := s.DeepCopy()
			old.OwnerReferences[0].UID = "old"
			old.Endpoints[0].Addresses = []string{"10.0.0.3"}
			return []*discovery.EndpointSlice{old, s}
		}, "ready"},
		{"TCP", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.Ports[0].Protocol = ptr(core.ProtocolTCP)
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"wrong port", func(_ *core.Service, s *discovery.EndpointSlice) []*discovery.EndpointSlice {
			s.Ports[0].Name = ptr("other")
			return []*discovery.EndpointSlice{s}
		}, "missing"},
		{"service deletion", func(s *core.Service, e *discovery.EndpointSlice) []*discovery.EndpointSlice {
			now := meta.Now()
			s.DeletionTimestamp = &now
			return []*discovery.EndpointSlice{e}
		}, "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, slice := serviceFixture()
			slices := tc.change(service, slice)
			endpoint, state := SelectEndpoint(service, slices, "wg")
			if state != tc.state {
				t.Fatalf("state %s expected %s", state, tc.state)
			}
			if state == "ready" && (endpoint == nil || endpoint.String() != "10.0.0.2:51820") {
				t.Fatalf("unexpected endpoint %v", endpoint)
			}
		})
	}
}
