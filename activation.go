package wglink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// ActivationFence must fail closed independently of process scheduling. Both the
// absolute deadline and relative TTL must be enforced; combined clock faults are
// outside that guarantee. Close must confirm the kernel gate is closed.
type ActivationFence interface {
	InstallClosed(context.Context) error
	AllowUntil(context.Context, time.Time, time.Time) error
	Close(context.Context) error
}

// Activation coordinates a generic, optional whole-group lease and kernel gate.
// Pod observations and successful own-holder write request starts bound freshness;
// GETs and election callbacks alone never authorize traffic.
type Activation struct {
	mu                           sync.Mutex
	client                       kubernetes.Interface
	config                       ActivationConfig
	identity                     PodIdentity
	fence                        ActivationFence
	notify                       func()
	candidate                    bool
	observed, ack, allowed       time.Time
	retryNotBefore               time.Time
	generation                   uint64
	leading, configured, running bool
	cancelElection               context.CancelFunc
}

func NewActivation(client kubernetes.Interface, config ActivationConfig, identity PodIdentity, guard ActivationFence, notify func()) (*Activation, error) {
	if client == nil || guard == nil {
		return nil, errors.New("activation requires Kubernetes client and fence")
	}
	if identity.Namespace == "" || identity.Name == "" || identity.UID == "" || identity.ContainerName == "" {
		return nil, errors.New("activation requires complete pod identity")
	}
	if config.KubernetesLease.Namespace == "" {
		config.KubernetesLease.Namespace = identity.Namespace
	}
	if config.KubernetesLease.Name == "" {
		return nil, errors.New("activation requires lease name")
	}
	if config.KubernetesLease.LeaseDuration == 0 {
		config.KubernetesLease.LeaseDuration = 15 * time.Second
	}
	if config.KubernetesLease.RenewDeadline == 0 {
		config.KubernetesLease.RenewDeadline = 10 * time.Second
	}
	if config.KubernetesLease.RetryPeriod == 0 {
		config.KubernetesLease.RetryPeriod = time.Second
	}
	if config.FenceTimeout == 0 {
		config.FenceTimeout = 3 * time.Second
	}
	for _, name := range config.KubernetesLease.RequireReadyContainers {
		if name == identity.ContainerName {
			return nil, errors.New("activation cannot require its own container readiness")
		}
	}
	return &Activation{client: client, config: config, identity: identity, fence: guard, notify: notify}, nil
}
func (a *Activation) signal() {
	if a.notify != nil {
		a.notify()
	}
}
func (a *Activation) eligibleLocked(now time.Time) bool {
	return a.candidate && !now.Before(a.retryNotBefore) && now.Before(a.observed.Add(a.config.KubernetesLease.RenewDeadline))
}
func (a *Activation) selectedLocked(now time.Time) bool {
	return a.leading && a.eligibleLocked(now) && !a.ack.IsZero() && now.Before(a.ack.Add(a.config.KubernetesLease.RenewDeadline))
}
func (a *Activation) Eligible() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.eligibleLocked(time.Now())
}
func (a *Activation) Selected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.selectedLocked(time.Now())
}
func (a *Activation) Ready() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	return a.configured && a.selectedLocked(now) && now.Before(a.allowed)
}
func (a *Activation) SetConfigured(v bool) { a.mu.Lock(); a.configured = v; a.mu.Unlock() }

// ConfigurationFailed yields ownership when the selected interface group cannot
// be applied. It prevents renewed competition for RenewDeadline so another
// healthy candidate can serve. Run confirms fencing before releasing the lease;
// callers needing synchronous closure must also call ReconcileGuard.
func (a *Activation) ConfigurationFailed() {
	a.mu.Lock()
	a.retryNotBefore = time.Now().Add(a.config.KubernetesLease.RenewDeadline)
	a.invalidateLocked()
	a.mu.Unlock()
	a.signal()
}

// ReconcileGuard serializes all gate writes with leadership invalidation. It
// computes deadlines before kernel I/O, so delayed responses cannot extend them.
func (a *Activation) ReconcileGuard(ctx context.Context) error {
	a.mu.Lock()
	notify := false
	defer func() {
		a.mu.Unlock()
		if notify {
			a.signal()
		}
	}()
	now := time.Now()
	if !a.selectedLocked(now) || !a.configured {
		a.allowed = time.Time{}
		if !a.selectedLocked(now) {
			a.configured = false
		}
		return a.fence.Close(ctx)
	}
	deadline := now.Add(a.config.FenceTimeout)
	for _, d := range []time.Time{a.ack.Add(a.config.KubernetesLease.RenewDeadline), a.observed.Add(a.config.KubernetesLease.RenewDeadline)} {
		if d.Before(deadline) {
			deadline = d
		}
	}
	// The kernel's absolute-time expression has whole-second precision. A
	// deadline rounded into the current second cannot authorize another refresh;
	// demote normally rather than treating expected expiry as a kernel failure.
	if deadline.Unix() <= time.Now().Unix() {
		a.invalidateLocked()
		notify = true
		return a.fence.Close(ctx)
	}
	if err := a.fence.AllowUntil(ctx, deadline, now); err != nil {
		a.allowed = time.Time{}
		return err
	}
	a.allowed = deadline
	return nil
}
func (a *Activation) podEligible(p *corev1.Pod) bool {
	if string(p.UID) != a.identity.UID || p.Spec.HostNetwork || p.DeletionTimestamp != nil {
		return false
	}
	declared := map[string]bool{}
	for _, c := range p.Spec.Containers {
		declared[c.Name] = true
	}
	statuses := map[string]corev1.ContainerStatus{}
	for _, s := range p.Status.ContainerStatuses {
		statuses[s.Name] = s
	}
	for _, name := range a.config.KubernetesLease.RequireReadyContainers {
		s, ok := statuses[name]
		if name == a.identity.ContainerName || !declared[name] || !ok || !s.Ready || s.State.Running == nil {
			return false
		}
	}
	return true
}
func (a *Activation) poll(ctx context.Context) error {
	start := time.Now()
	request, cancel := context.WithTimeout(ctx, 2*time.Second)
	p, err := a.client.CoreV1().Pods(a.identity.Namespace).Get(request, a.identity.Name, metav1.GetOptions{})
	cancel()
	a.mu.Lock()
	previous := a.eligibleLocked(time.Now())
	wasActive := a.leading || a.configured
	// A failed read supplies no new observation. Retain the last successful
	// kubelet state only until its original renewal deadline; failures cannot
	// extend it. An explicit unhealthy observation invalidates immediately.
	if err == nil {
		a.candidate = a.podEligible(p) && time.Now().Before(start.Add(a.config.KubernetesLease.RenewDeadline))
		a.observed = start
	}
	var fenceErr error
	if !a.eligibleLocked(time.Now()) {
		a.invalidateLocked()
		fenceErr = a.fence.Close(ctx)
	}
	changed := previous != a.eligibleLocked(time.Now()) || (wasActive && !a.eligibleLocked(time.Now()))
	a.mu.Unlock()
	if changed {
		a.signal()
	}
	return fenceErr
}
func (a *Activation) invalidateLocked() {
	a.generation++
	a.leading = false
	a.configured = false
	a.ack = time.Time{}
	a.allowed = time.Time{}
	if a.cancelElection != nil {
		a.cancelElection()
	}
}

// Run installs a closed gate before starting any election, and joins all API
// workers before returning. Failed API reads retain the last successful Pod
// observation only until RenewDeadline (10s by default). The kernel heartbeat
// remains separately bounded by FenceTimeout (3s by default).
func (a *Activation) Run(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return errors.New("activation already running")
	}
	a.running = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.running = false; a.mu.Unlock() }()
	if err := a.fence.InstallClosed(ctx); err != nil {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	workerErrors := make(chan error, 1)
	lock := &activationLeaseLock{Interface: &resourcelock.LeaseLock{LeaseMeta: metav1.ObjectMeta{Namespace: a.config.KubernetesLease.Namespace, Name: a.config.KubernetesLease.Name}, Client: a.client.CoordinationV1(), LockConfig: resourcelock.ResourceLockConfig{Identity: a.identity.UID}}, activation: a}
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{Lock: lock, LeaseDuration: a.config.KubernetesLease.LeaseDuration, RenewDeadline: a.config.KubernetesLease.RenewDeadline, RetryPeriod: a.config.KubernetesLease.RetryPeriod, ReleaseOnCancel: false, Callbacks: leaderelection.LeaderCallbacks{OnStartedLeading: func(context.Context) {}, OnStoppedLeading: func() { a.mu.Lock(); a.invalidateLocked(); a.mu.Unlock(); a.signal() }}})
	if err != nil {
		cancel()
		return fmt.Errorf("activation election: %w", err)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		pollTicker := time.NewTicker(time.Second)
		defer pollTicker.Stop()
		for {
			if err := a.poll(workerCtx); err != nil && workerCtx.Err() == nil {
				select {
				case workerErrors <- err:
				default:
				}
				return
			}
			select {
			case <-workerCtx.Done():
				return
			case <-pollTicker.C:
			}
		}
	}()
	go func() {
		defer wg.Done()
		for workerCtx.Err() == nil {
			ec, stop := context.WithCancel(workerCtx)
			a.mu.Lock()
			a.cancelElection = stop
			a.mu.Unlock()
			elector.Run(ec)
			stop()
			a.mu.Lock()
			cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
			closeErr := a.fence.Close(cleanup)
			if closeErr == nil {
				_ = a.release(cleanup)
			}
			finish()
			a.mu.Unlock()
			if closeErr != nil {
				select {
				case workerErrors <- closeErr:
				default:
				}
				return
			}
			select {
			case <-workerCtx.Done():
				return
			case <-time.After(a.config.KubernetesLease.RetryPeriod):
			}
		}
	}()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-workerErrors:
			runErr = err
			break loop
		case <-ticker.C:
			a.mu.Lock()
			lost := (!a.eligibleLocked(time.Now()) || (!a.ack.IsZero() && !time.Now().Before(a.ack.Add(a.config.KubernetesLease.RenewDeadline)))) && (a.leading || a.configured)
			if lost {
				a.invalidateLocked()
			}
			a.mu.Unlock()
			if lost {
				a.signal()
			}
			if err := a.ReconcileGuard(workerCtx); err != nil {
				runErr = err
				break loop
			}
		}
	}
	cancel()
	wg.Wait()
	a.mu.Lock()
	a.invalidateLocked()
	a.mu.Unlock()
	a.signal()
	cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	if err := a.fence.Close(cleanup); err != nil {
		return errors.Join(runErr, err)
	}
	return errors.Join(runErr, a.release(cleanup))
}
