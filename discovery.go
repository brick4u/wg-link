package wglink

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type namespaceCache struct {
	services cache.SharedIndexInformer
	slices   cache.SharedIndexInformer
	failed   []*atomic.Bool
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
		d.namespaces[ns] = namespaceCache{services: s, slices: e, failed: failures}
		f.Start(ctx.Done())
	}
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
		if !n.services.HasSynced() || !n.slices.HasSynced() {
			return true
		}
	}
	return false
}
func (d *Discovery) Synced() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, n := range d.namespaces {
		if !n.services.HasSynced() || !n.slices.HasSynced() {
			return false
		}
	}
	return true
}
func (d *Discovery) Resolve(r ServiceRef) (*net.UDPAddr, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	n, ok := d.namespaces[r.Namespace]
	if !ok || !n.services.HasSynced() || !n.slices.HasSynced() {
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
	return SelectEndpoint(obj.(*core.Service), slices, r.Port)
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
