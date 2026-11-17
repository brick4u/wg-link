package wglink

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	coordination "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type namespaceCache struct {
	factory     informers.SharedInformerFactory
	services    cache.SharedIndexInformer
	slices      cache.SharedIndexInformer
	leases      cache.SharedIndexInformer
	leaseFailed *atomic.Bool
	failed      []*atomic.Bool
}
type Discovery struct {
	namespaces map[string]namespaceCache
	Errors     atomic.Uint64
	mu         sync.RWMutex
	ctx        context.Context
	client     kubernetes.Interface
	notify     func()
}

func NewDiscovery(ctx context.Context, client kubernetes.Interface, namespaces []string, notify func()) *Discovery {
	d := &Discovery{namespaces: map[string]namespaceCache{}, ctx: ctx, client: client, notify: notify}
	d.EnsureNamespaces(namespaces)
	return d
}
func (d *Discovery) EnsureNamespaces(namespaces []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, client, notify := d.ctx, d.client, d.notify
	for _, ns := range namespaces {
		if _, ok := d.namespaces[ns]; ok {
			continue
		}
		f := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(ns))
		s := f.Core().V1().Services().Informer()
		e := f.Discovery().V1().EndpointSlices().Informer()
		failures := []*atomic.Bool{}
		for _, in := range []cache.SharedIndexInformer{s, e} {
			failed := &atomic.Bool{}
			failures = append(failures, failed)
			changed := func() { failed.Store(false); notify() }
			handler := cache.ResourceEventHandlerFuncs{AddFunc: func(any) { changed() }, UpdateFunc: func(any, any) { changed() }, DeleteFunc: func(any) { changed() }}
			_, _ = in.AddEventHandler(handler)
			_ = in.SetWatchErrorHandler(func(_ *cache.Reflector, _ error) { d.Errors.Add(1); failed.Store(true); notify() })
		}
		d.namespaces[ns] = namespaceCache{factory: f, services: s, slices: e, failed: failures}
		f.Start(ctx.Done())
	}
}

// ensureLeaseWatch activates coordination discovery only for lease-scoped references.
// Call before taking d.mu.RLock; starting the factory a second time starts only new informers.
func (d *Discovery) ensureLeaseWatch(namespace string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, ok := d.namespaces[namespace]
	if !ok || n.leases != nil {
		return
	}
	l := n.factory.Coordination().V1().Leases().Informer()
	failed := &atomic.Bool{}
	changed := func() { failed.Store(false); d.notify() }
	_, _ = l.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { changed() }, UpdateFunc: func(any, any) { changed() }, DeleteFunc: func(any) { changed() },
	})
	_ = l.SetWatchErrorHandler(func(_ *cache.Reflector, _ error) { d.Errors.Add(1); failed.Store(true); d.notify() })
	n.leases = l
	n.leaseFailed = failed
	n.failed = append(n.failed, failed)
	d.namespaces[namespace] = n
	n.factory.Start(d.ctx.Done())
}

// Degraded is conservative: a failed watch stays degraded until that informer receives an event/relist.
func (d *Discovery) Degraded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, n := range d.namespaces {
		for _, failed := range n.failed {
			if failed.Load() {
				return true
			}
		}
		if !n.services.HasSynced() || !n.slices.HasSynced() || (n.leases != nil && !n.leases.HasSynced()) {
			return true
		}
	}
	return false
}
func (d *Discovery) Synced() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, n := range d.namespaces {
		if !n.services.HasSynced() || !n.slices.HasSynced() || (n.leases != nil && !n.leases.HasSynced()) {
			return false
		}
	}
	return true
}
func (d *Discovery) Resolve(r ServiceRef) (*net.UDPAddr, string) {
	if r.LeaseName != "" {
		d.ensureLeaseWatch(r.Namespace)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	n, ok := d.namespaces[r.Namespace]
	if !ok || !n.services.HasSynced() || !n.slices.HasSynced() || (r.LeaseName != "" && (n.leases == nil || !n.leases.HasSynced())) {
		return nil, "missing"
	}
	obj, exists, _ := n.services.GetStore().GetByKey(r.Namespace + "/" + r.Name)
	if !exists {
		return nil, "missing"
	}
	slices := []*discovery.EndpointSlice{}
	for _, o := range n.slices.GetStore().List() {
		slices = append(slices, o.(*discovery.EndpointSlice))
	}
	if r.LeaseName == "" {
		return SelectEndpoint(obj.(*core.Service), slices, r.Port)
	}
	if n.leaseFailed.Load() {
		return nil, "missing"
	}
	leaseObj, exists, err := n.leases.GetStore().GetByKey(r.Namespace + "/" + r.LeaseName)
	if err != nil || !exists {
		return nil, "missing"
	}
	lease := leaseObj.(*coordination.Lease)
	if lease.Namespace != r.Namespace || lease.Name != r.LeaseName || lease.DeletionTimestamp != nil ||
		lease.Spec.HolderIdentity == nil || lease.Spec.LeaseDurationSeconds == nil || *lease.Spec.LeaseDurationSeconds <= 0 {
		return nil, "missing"
	}
	holder := *lease.Spec.HolderIdentity
	if _, err := uuid.Parse(holder); err != nil {
		return nil, "missing"
	}
	lastRenewal := lease.Spec.RenewTime
	if lastRenewal == nil {
		lastRenewal = lease.Spec.AcquireTime
	}
	if lastRenewal == nil || !lastRenewal.Time.Add(time.Duration(*lease.Spec.LeaseDurationSeconds)*time.Second).After(time.Now().UTC()) {
		return nil, "missing"
	}
	return SelectEndpointForHolder(obj.(*core.Service), slices, r.Port, holder)
}

// SelectEndpointForHolder excludes endpoints not owned by the current Pod lease holder.
// Copies avoid changing informer-owned EndpointSlices or their endpoint backing arrays.
func SelectEndpointForHolder(service *core.Service, slices []*discovery.EndpointSlice, port, holderUID string) (*net.UDPAddr, string) {
	filtered := make([]*discovery.EndpointSlice, 0, len(slices))
	for _, slice := range slices {
		copySlice := *slice
		copySlice.Endpoints = make([]discovery.Endpoint, 0, len(slice.Endpoints))
		for _, endpoint := range slice.Endpoints {
			ref := endpoint.TargetRef
			if ref != nil && ref.Kind == "Pod" && ref.UID == types.UID(holderUID) &&
				ref.Namespace == slice.Namespace &&
				service != nil && slice.Namespace == service.Namespace {
				copySlice.Endpoints = append(copySlice.Endpoints, endpoint)
			}
		}
		filtered = append(filtered, &copySlice)
	}
	return SelectEndpoint(service, filtered, port)
}

func SelectEndpoint(service *core.Service, slices []*discovery.EndpointSlice, port string) (*net.UDPAddr, string) {
	if service == nil || service.UID == "" || service.DeletionTimestamp != nil {
		return nil, "missing"
	}
	validPort := false
	for _, p := range service.Spec.Ports {
		if p.Name == port && p.Protocol == core.ProtocolUDP {
			validPort = true
		}
	}
	if !validPort {
		return nil, "missing"
	}
	endpoints := map[netip.AddrPort]bool{}
	for _, s := range slices {
		if s.Namespace != service.Namespace || s.Labels[discovery.LabelServiceName] != service.Name || s.DeletionTimestamp != nil {
			continue
		}
		owned := false
		for _, o := range s.OwnerReferences {
			if o.UID == service.UID && o.Name == service.Name && o.Kind == "Service" && o.APIVersion == "v1" {
				owned = true
			}
		}
		if !owned {
			continue
		}
		for _, p := range s.Ports {
			if p.Name == nil || *p.Name != port || p.Protocol == nil || *p.Protocol != core.ProtocolUDP || p.Port == nil || *p.Port < 1 || *p.Port > 65535 {
				continue
			}
			for _, e := range s.Endpoints {
				if e.Conditions.Ready == nil || !*e.Conditions.Ready || (e.Conditions.Terminating != nil && *e.Conditions.Terminating) {
					continue
				}
				for _, a := range e.Addresses {
					ip, err := netip.ParseAddr(a)
					if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
						continue
					}
					if (s.AddressType == discovery.AddressTypeIPv4 && !ip.Is4()) || (s.AddressType == discovery.AddressTypeIPv6 && !ip.Is6()) || s.AddressType == discovery.AddressTypeFQDN {
						continue
					}
					endpoints[netip.AddrPortFrom(ip, uint16(*p.Port))] = true
				}
			}
		}
	}
	if len(endpoints) == 0 {
		return nil, "missing"
	}
	if len(endpoints) != 1 {
		return nil, "ambiguous"
	}
	for e := range endpoints {
		return net.UDPAddrFromAddrPort(e), "ready"
	}
	return nil, "missing"
}
