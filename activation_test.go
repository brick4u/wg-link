package wglink

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

type activationTestFence struct {
	mu     sync.Mutex
	open   bool
	allows int
	closes int
	err    error
}

func (f *activationTestFence) InstallClosed(ctx context.Context) error { return f.Close(ctx) }
func (f *activationTestFence) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open = false
	f.closes++
	return f.err
}
func (f *activationTestFence) AllowUntil(_ context.Context, d, s time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open = time.Now().Before(d)
	f.allows++
	return f.err
}
func (f *activationTestFence) isOpen() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.open }
func activationFixture(t *testing.T) (*Activation, *fake.Clientset, *activationTestFence, *corev1.Pod) {
	t.Helper()
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "pod", UID: "uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "wg"}, {Name: "app"}, {Name: "other"}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	client := fake.NewClientset(p)
	f := &activationTestFence{}
	a, err := NewActivation(client, ActivationConfig{KubernetesLease: KubernetesLeaseConfig{Name: "group", RequireReadyContainers: []string{"app"}}}, PodIdentity{Namespace: "test", Name: "pod", UID: "uid", ContainerName: "wg"}, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, client, f, p
}
func TestActivationCandidateUsesOnlyNamedContainerReadiness(t *testing.T) {
	a, _, _, p := activationFixture(t)
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	if !a.podEligible(p) {
		t.Fatal("unnamed containers and PodReady must not gate selection")
	}
	cases := map[string]func(*corev1.Pod){"uid": func(p *corev1.Pod) { p.UID = "wrong" }, "host network": func(p *corev1.Pod) { p.Spec.HostNetwork = true }, "termination": func(p *corev1.Pod) { now := metav1.Now(); p.DeletionTimestamp = &now }, "missing status": func(p *corev1.Pod) { p.Status.ContainerStatuses = nil }, "not running": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Running = nil }, "not ready": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].Ready = false }, "undeclared": func(p *corev1.Pod) { p.Spec.Containers = p.Spec.Containers[:1] }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			copy := p.DeepCopy()
			change(copy)
			if a.podEligible(copy) {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
	a.config.KubernetesLease.RequireReadyContainers = []string{"wg"}
	if a.podEligible(p) {
		t.Fatal("own container accepted")
	}
}
func TestActivationReadyRequiresConfiguredFreshAuthority(t *testing.T) {
	a, _, f, _ := activationFixture(t)
	a.candidate = true
	a.observed = time.Now()
	a.ack = time.Now()
	a.leading = true
	if !a.Selected() || a.Ready() {
		t.Fatal("selection must precede configured readiness")
	}
	if err := a.ReconcileGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.isOpen() {
		t.Fatal("opened before configuration")
	}
	a.SetConfigured(true)
	if err := a.ReconcileGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.Ready() {
		t.Fatal("configured current authority not ready")
	}
	a.mu.Lock()
	a.observed = time.Now().Add(-a.config.KubernetesLease.RenewDeadline)
	a.mu.Unlock()
	if a.Ready() || a.Selected() {
		t.Fatal("stale pod observation authorized traffic")
	}
	if err := a.ReconcileGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.isOpen() || a.configured {
		t.Fatal("stale authority not fenced/reset")
	}
}
func TestActivationSubsecondDeadlineDemotesNormally(t *testing.T) {
	a, _, f, _ := activationFixture(t)
	now := time.Now()
	// Half the remaining current second ensures a future deadline whose
	// whole-second representation is already unusable by the kernel guard.
	remaining := time.Until(now.Truncate(time.Second).Add(time.Second))
	if remaining < 100*time.Millisecond {
		t.Skip("current second is too close to its boundary")
	}
	deadline := now.Add(remaining / 2)
	a.candidate = true
	a.observed = now
	a.leading = true
	a.configured = true
	a.ack = deadline.Add(-a.config.KubernetesLease.RenewDeadline)
	notified := false
	a.notify = func() { notified = true }
	cancelled := false
	a.cancelElection = func() { cancelled = true }
	if err := a.ReconcileGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.allows != 0 || f.closes != 1 || a.configured || a.leading || !notified || !cancelled {
		t.Fatal("subsecond expiry did not close and demote normally")
	}
}

func TestActivationPodReadFailureRetainsOnlyUnexpiredObservation(t *testing.T) {
	for _, mode := range []string{"transient error", "expired error", "explicit unhealthy"} {
		t.Run(mode, func(t *testing.T) {
			a, client, f, _ := activationFixture(t)
			notified := false
			a.notify = func() { notified = true }
			a.candidate = true
			a.observed = time.Now()
			a.ack = time.Now()
			a.leading = true
			a.configured = true
			if err := a.ReconcileGuard(context.Background()); err != nil {
				t.Fatal(err)
			}
			observed := a.observed
			if mode == "expired error" {
				a.observed = time.Now().Add(-a.config.KubernetesLease.RenewDeadline)
				observed = a.observed
			}
			client.PrependReactor("get", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
				if mode == "explicit unhealthy" {
					p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid"}}
					return true, p, nil
				}
				return true, nil, errors.New("API temporarily unavailable")
			})
			if err := a.poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if mode == "transient error" {
				if !a.Selected() || !a.Ready() || !f.isOpen() || a.observed != observed {
					t.Fatal("transient read error invalidated or extended fresh observation")
				}
			} else if a.Selected() || a.Ready() || f.isOpen() || a.configured || !notified {
				t.Fatal("expired or explicitly unhealthy observation was not fenced")
			}
		})
	}
}

func TestActivationLeaseWriteProofAndGeneration(t *testing.T) {
	for _, mode := range []string{"unhealthy", "success", "generation", "expired", "failure"} {
		t.Run(mode, func(t *testing.T) {
			a, client, _, _ := activationFixture(t)
			a.candidate = mode != "unhealthy"
			a.observed = time.Now()
			if mode == "expired" {
				a.config.KubernetesLease.RenewDeadline = time.Nanosecond
			}
			client.PrependReactor("create", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
				if mode == "generation" {
					a.mu.Lock()
					a.invalidateLocked()
					a.mu.Unlock()
				}
				if mode == "failure" {
					return true, nil, errors.New("unavailable")
				}
				return false, nil, nil
			})
			lock := &activationLeaseLock{Interface: &resourcelock.LeaseLock{LeaseMeta: metav1.ObjectMeta{Namespace: "test", Name: "group"}, Client: client.CoordinationV1(), LockConfig: resourcelock.ResourceLockConfig{Identity: "uid"}}, activation: a}
			err := lock.Create(context.Background(), resourcelock.LeaderElectionRecord{HolderIdentity: "uid", LeaseDurationSeconds: 15})
			if mode == "success" {
				if err != nil || !a.Selected() {
					t.Fatalf("acknowledged owner not selected: %v", err)
				}
			} else {
				if err == nil || !a.ack.IsZero() {
					t.Fatal("invalid acknowledgement accepted")
				}
			}
			// The decorator never blocks reads, including while unhealthy.
			_, _, _ = lock.Get(context.Background())
			found := false
			for _, action := range client.Actions() {
				if action.GetVerb() == "get" {
					found = true
				}
			}
			if !found {
				t.Fatal("GET blocked")
			}
		})
	}
}
func TestActivationRunClosesBeforeOwnRelease(t *testing.T) {
	a, client, f, _ := activationFixture(t)
	a.config.KubernetesLease.RetryPeriod = 100 * time.Millisecond
	client.PrependReactor("update", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		lease := action.(ktesting.UpdateAction).GetObject().(*coordinationv1.Lease)
		if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == "" && f.isOpen() {
			t.Error("released lease before confirmed fence")
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for !a.Selected() {
		select {
		case err := <-done:
			t.Fatalf("Run ended: %v", err)
		case <-deadline:
			cancel()
			<-done
			t.Fatal("election timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
	a.SetConfigured(true)
	if err := a.ReconcileGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.Ready() {
		t.Fatal("active group not ready")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.isOpen() || a.Ready() {
		t.Fatal("shutdown left gate open")
	}
	lease, err := client.CoordinationV1().Leases("test").Get(context.Background(), "group", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "" {
		t.Fatal("own lease not released")
	}
	actions := len(client.Actions())
	time.Sleep(30 * time.Millisecond)
	if len(client.Actions()) != actions {
		t.Fatal("API calls continued after Run returned")
	}
}
func TestActivationAcknowledgementExpiryAndGateFailure(t *testing.T) {
	a, _, f, _ := activationFixture(t)
	a.candidate = true
	a.observed = time.Now()
	a.leading = true
	a.configured = true
	a.ack = time.Now().Add(-a.config.KubernetesLease.RenewDeadline)
	if a.Selected() || a.Ready() {
		t.Fatal("expired write acknowledgement authorized traffic")
	}
	a.ack = time.Now()
	f.err = errors.New("kernel gate unavailable")
	if err := a.ReconcileGuard(context.Background()); err == nil {
		t.Fatal("gate failure ignored")
	}
	if a.Ready() {
		t.Fatal("failed gate operation reported ready")
	}
}

func TestActivationReleaseDoesNotReleaseAnotherHolder(t *testing.T) {
	a, client, _, _ := activationFixture(t)
	other := "other"
	_, err := client.CoordinationV1().Leases("test").Create(context.Background(), &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "group"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &other}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" {
			t.Fatal("updated another holder")
		}
	}
}
