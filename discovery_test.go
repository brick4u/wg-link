package wglink

import (
	"context"
	"errors"
	"testing"
	"time"

	coordination "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
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
	ref := ServiceRef{Namespace: "ns", Name: "peer", Port: "wg"}
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
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "leases" {
			t.Fatalf("unscoped discovery accessed leases: %s", action.GetVerb())
		}
	}
	if d.Degraded() {
		t.Fatal("unscoped discovery should not require lease access")
	}
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

const (
	oldPodUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	newPodUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func TestSelectEndpointForHolder(t *testing.T) {
	for _, tc := range []struct {
		name           string
		change         func(*core.Service, *discovery.EndpointSlice)
		state, address string
	}{
		{"old ready and new ready", func(_ *core.Service, _ *discovery.EndpointSlice) {}, "ready", "10.0.0.3:51820"},
		{"no ready holder", func(_ *core.Service, s *discovery.EndpointSlice) { s.Endpoints[1].Conditions.Ready = ptr(false) }, "missing", ""},
		{"two ready holder addresses", func(_ *core.Service, s *discovery.EndpointSlice) {
			s.Endpoints[1].Addresses = []string{"10.0.0.3", "10.0.0.4"}
		}, "ambiguous", ""},
		{"wrong holder UID", func(_ *core.Service, s *discovery.EndpointSlice) { s.Endpoints[1].TargetRef.UID = "other" }, "missing", ""},
		{"wrong holder namespace", func(_ *core.Service, s *discovery.EndpointSlice) { s.Endpoints[1].TargetRef.Namespace = "elsewhere" }, "missing", ""},
		{"non Pod target", func(_ *core.Service, s *discovery.EndpointSlice) { s.Endpoints[1].TargetRef.Kind = "Node" }, "missing", ""},
		{"terminating holder", func(_ *core.Service, s *discovery.EndpointSlice) { s.Endpoints[1].Conditions.Terminating = ptr(true) }, "missing", ""},
		{"unowned slice", func(_ *core.Service, s *discovery.EndpointSlice) { s.OwnerReferences = nil }, "missing", ""},
		{"wrong port", func(_ *core.Service, s *discovery.EndpointSlice) { s.Ports[0].Port = nil }, "missing", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, slice := serviceFixture()
			slice.Endpoints[0].TargetRef = &core.ObjectReference{Kind: "Pod", Namespace: "ns", UID: oldPodUID}
			slice.Endpoints = append(slice.Endpoints, discovery.Endpoint{Addresses: []string{"10.0.0.3"}, Conditions: discovery.EndpointConditions{Ready: ptr(true)}, TargetRef: &core.ObjectReference{Kind: "Pod", Namespace: "ns", UID: newPodUID}})
			tc.change(service, slice)
			original := slice.DeepCopy()
			endpoint, state := SelectEndpointForHolder(service, []*discovery.EndpointSlice{slice}, "wg", newPodUID)
			if state != tc.state || (tc.address != "" && (endpoint == nil || endpoint.String() != tc.address)) {
				t.Fatalf("got %s %v, want %s %s", state, endpoint, tc.state, tc.address)
			}
			if len(slice.Endpoints) != len(original.Endpoints) || slice.Endpoints[0].Addresses[0] != original.Endpoints[0].Addresses[0] {
				t.Fatal("modified input slice")
			}
		})
	}
}

func TestLeaseScopedInformer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service, slice := serviceFixture()
	slice.Endpoints[0].TargetRef = &core.ObjectReference{Kind: "Pod", Namespace: "ns", UID: oldPodUID}
	slice.Endpoints = append(slice.Endpoints, discovery.Endpoint{Addresses: []string{"10.0.0.3"}, Conditions: discovery.EndpointConditions{Ready: ptr(true)}, TargetRef: &core.ObjectReference{Kind: "Pod", Namespace: "ns", UID: newPodUID}})
	lease := &coordination.Lease{ObjectMeta: meta.ObjectMeta{Name: "leader", Namespace: "ns"}, Spec: coordination.LeaseSpec{HolderIdentity: ptr(newPodUID), LeaseDurationSeconds: ptr(int32(60)), RenewTime: &meta.MicroTime{Time: time.Now().UTC()}}}
	client := fake.NewClientset(service, slice, lease)
	d := NewDiscovery(ctx, client, []string{"ns"}, func() {})
	ref := ServiceRef{Namespace: "ns", Name: "peer", Port: "wg", LeaseName: "leader"}
	d.Resolve(ref) // Activate the lease informer before waiting for cache sync.
	if !cache.WaitForCacheSync(ctx.Done(), d.Synced) || d.Degraded() {
		t.Fatal("lease informer did not sync")
	}
	await := func(state, address string) {
		t.Helper()
		for {
			e, s := d.Resolve(ref)
			if s == state && (address == "" || (e != nil && e.String() == address)) {
				return
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				t.Fatalf("got %s %v, want %s %s", s, e, state, address)
			}
		}
	}
	await("ready", "10.0.0.3:51820")
	ref.LeaseName = "absent"
	await("missing", "")
	ref.LeaseName = "leader"
	lease.Spec.HolderIdentity = ptr(oldPodUID)
	if _, err := client.CoordinationV1().Leases("ns").Update(ctx, lease, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	await("ready", "10.0.0.2:51820")
	lease.Spec.RenewTime = &meta.MicroTime{Time: time.Now().UTC().Add(-2 * time.Minute)}
	if _, err := client.CoordinationV1().Leases("ns").Update(ctx, lease, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	await("missing", "")
	ref.LeaseName = ""
	await("ambiguous", "")
}

func TestLeaseWatchFailureDegraded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service, slice := serviceFixture()
	client := fake.NewClientset(service, slice)
	client.PrependWatchReactor("leases", func(ktesting.Action) (bool, watch.Interface, error) {
		return true, nil, errors.New("lease watch unavailable")
	})
	d := NewDiscovery(ctx, client, []string{"ns"}, func() {})
	d.Resolve(ServiceRef{Namespace: "ns", Name: "peer", Port: "wg", LeaseName: "leader"})
	if !cache.WaitForCacheSync(ctx.Done(), d.Synced) {
		t.Fatal("informers did not sync")
	}
	for !d.Degraded() {
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("lease watch failure did not degrade discovery")
		}
	}
	if d.Errors.Load() == 0 {
		t.Fatal("lease watch failure not counted")
	}
}

func TestInvalidLeases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	service, slice := serviceFixture()
	slice.Endpoints[0].TargetRef = &core.ObjectReference{Kind: "Pod", Namespace: "ns", UID: newPodUID}
	lease := &coordination.Lease{ObjectMeta: meta.ObjectMeta{Name: "leader", Namespace: "ns"}, Spec: coordination.LeaseSpec{HolderIdentity: ptr(newPodUID), LeaseDurationSeconds: ptr(int32(60)), AcquireTime: &meta.MicroTime{Time: time.Now().UTC()}}}
	client := fake.NewClientset(service, slice, lease)
	d := NewDiscovery(ctx, client, []string{"ns"}, func() {})
	ref := ServiceRef{Namespace: "ns", Name: "peer", Port: "wg", LeaseName: "leader"}
	d.Resolve(ref)
	if !cache.WaitForCacheSync(ctx.Done(), d.Synced) {
		t.Fatal("informers did not sync")
	}
	if _, state := d.Resolve(ref); state != "ready" {
		t.Fatalf("acquire timestamp should be usable, got %s", state)
	}
	for _, tc := range []struct {
		name   string
		change func(*coordination.Lease)
	}{
		{"nil holder", func(l *coordination.Lease) { l.Spec.HolderIdentity = nil }},
		{"invalid holder", func(l *coordination.Lease) { l.Spec.HolderIdentity = ptr("not-a-pod-uid") }},
		{"nil duration", func(l *coordination.Lease) { l.Spec.LeaseDurationSeconds = nil }},
		{"zero duration", func(l *coordination.Lease) { l.Spec.LeaseDurationSeconds = ptr(int32(0)) }},
		{"nil timestamps", func(l *coordination.Lease) { l.Spec.AcquireTime = nil }},
		{"expired acquire", func(l *coordination.Lease) {
			l.Spec.AcquireTime = &meta.MicroTime{Time: time.Now().UTC().Add(-time.Hour)}
		}},
		{"expired renew", func(l *coordination.Lease) {
			l.Spec.RenewTime = &meta.MicroTime{Time: time.Now().UTC().Add(-time.Hour)}
		}},
		{"deleted lease", func(l *coordination.Lease) { now := meta.Now(); l.DeletionTimestamp = &now }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := lease.DeepCopy()
			tc.change(invalid)
			if err := d.namespaces["ns"].leases.GetStore().Update(invalid); err != nil {
				t.Fatal(err)
			}
			if _, state := d.Resolve(ref); state != "missing" {
				t.Fatalf("invalid lease resolved %s", state)
			}
			if err := d.namespaces["ns"].leases.GetStore().Update(lease); err != nil {
				t.Fatal(err)
			}
		})
	}
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
