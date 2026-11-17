package wglink

import (
	"context"
	"errors"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Reads remain available while unhealthy so the same standard elector continues
// observing the lease. Only acknowledged, current-generation own-holder writes
// can establish authority. Cancellation, GET and release are never proof.
type activationLeaseLock struct {
	resourcelock.Interface
	activation *Activation
}

func (l *activationLeaseLock) Create(ctx context.Context, record resourcelock.LeaderElectionRecord) error {
	return l.write(ctx, record, true)
}
func (l *activationLeaseLock) Update(ctx context.Context, record resourcelock.LeaderElectionRecord) error {
	return l.write(ctx, record, false)
}
func (l *activationLeaseLock) write(ctx context.Context, record resourcelock.LeaderElectionRecord, create bool) error {
	a := l.activation
	a.mu.Lock()
	start := time.Now()
	generation := a.generation
	permitted := a.eligibleLocked(start) && record.HolderIdentity == a.identity.UID
	a.mu.Unlock()
	if !permitted {
		return errors.New("activation candidate is not eligible")
	}
	var err error
	if create {
		err = l.Interface.Create(ctx, record)
	} else {
		err = l.Interface.Update(ctx, record)
	}
	a.mu.Lock()
	changed := false
	defer func() {
		a.mu.Unlock()
		if changed {
			a.signal()
		}
	}()
	if err != nil {
		return err
	}
	if generation != a.generation || !a.eligibleLocked(time.Now()) || !time.Now().Before(start.Add(a.config.KubernetesLease.RenewDeadline)) {
		return errors.New("activation lease acknowledgement expired")
	}
	changed = !a.leading
	a.leading = true
	a.ack = start
	return nil
}

// release is called only after election writers have stopped and fencing has
// succeeded. Kubernetes resourceVersion and UID preserve compare-and-swap safety.
func (a *Activation) release(ctx context.Context) error {
	leases := a.client.CoordinationV1().Leases(a.config.KubernetesLease.Namespace)
	lease, err := leases.Get(ctx, a.config.KubernetesLease.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != a.identity.UID {
		return nil
	}
	empty := ""
	duration := int32(1)
	lease.Spec.HolderIdentity = &empty
	lease.Spec.LeaseDurationSeconds = &duration
	_, err = leases.Update(ctx, lease, metav1.UpdateOptions{})
	return err
}
