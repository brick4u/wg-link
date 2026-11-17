package wglink

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// ActivationConfig optionally makes the whole declared interface group exclusive.
// Application health remains a kubelet readiness probe on the named containers.
type ActivationConfig struct {
	KubernetesLease KubernetesLeaseConfig `yaml:"kubernetesLease"`
	FenceTimeout    time.Duration         `yaml:"fenceTimeout"`
}

type KubernetesLeaseConfig struct {
	Namespace              string        `yaml:"namespace"`
	Name                   string        `yaml:"name"`
	RequireReadyContainers []string      `yaml:"requireReadyContainers"`
	LeaseDuration          time.Duration `yaml:"leaseDuration"`
	RenewDeadline          time.Duration `yaml:"renewDeadline"`
	RetryPeriod            time.Duration `yaml:"retryPeriod"`
}

// ValidateActivationReload prevents a hot reload from bypassing the retained
// kernel boundary with an unguarded port. Peer, route and key reloads remain
// supported; activation settings and the protected port set require restart.
func ValidateActivationReload(initial, next *Config) error {
	if !reflect.DeepEqual(initial.Activation, next.Activation) {
		return fmt.Errorf("activation settings require a process restart")
	}
	if initial.Activation == nil {
		return nil
	}
	ports := func(c *Config) []int {
		p := make([]int, 0, len(c.Interfaces))
		for _, n := range c.Interfaces {
			p = append(p, n.ListenPort)
		}
		sort.Ints(p)
		return p
	}
	if !reflect.DeepEqual(ports(initial), ports(next)) {
		return fmt.Errorf("activation listen-port set requires a process restart")
	}
	return nil
}

// PodIdentity is supplied through the Kubernetes Downward API, not inferred from
// interface addresses or a container hostname. The API must confirm its UID.
type PodIdentity struct {
	Namespace     string
	Name          string
	UID           string
	ContainerName string
}

func validateActivation(c *Config) error {
	for _, n := range c.Interfaces {
		for _, p := range n.Peers {
			if p.Service != nil && p.Service.LeaseName != "" && len(validation.IsDNS1123Subdomain(p.Service.LeaseName)) != 0 {
				return fmt.Errorf("service leaseName must be a Kubernetes resource name")
			}
		}
	}
	if c.Activation == nil {
		return nil
	}
	a := c.Activation
	l := &a.KubernetesLease
	if l.Name == "" || len(validation.IsDNS1123Subdomain(l.Name)) != 0 {
		return fmt.Errorf("activation requires a valid Kubernetes lease name")
	}
	if l.Namespace != "" && len(validation.IsDNS1123Label(l.Namespace)) != 0 {
		return fmt.Errorf("invalid activation lease namespace")
	}
	if l.LeaseDuration == 0 {
		l.LeaseDuration = 15 * time.Second
	}
	if l.RenewDeadline == 0 {
		l.RenewDeadline = 10 * time.Second
	}
	if l.RetryPeriod == 0 {
		l.RetryPeriod = time.Second
	}
	if a.FenceTimeout == 0 {
		a.FenceTimeout = 3 * time.Second
	}
	if l.LeaseDuration < 5*time.Second || l.LeaseDuration > 5*time.Minute || l.LeaseDuration%time.Second != 0 {
		return fmt.Errorf("leaseDuration must be whole seconds between 5s and 5m")
	}
	if l.RenewDeadline < time.Second || l.RetryPeriod < 100*time.Millisecond || l.RenewDeadline <= 2*l.RetryPeriod {
		return fmt.Errorf("renewDeadline must exceed twice the positive retryPeriod")
	}
	if a.FenceTimeout < 2*time.Second || a.FenceTimeout > l.RenewDeadline || l.LeaseDuration <= l.RenewDeadline+a.FenceTimeout+l.RetryPeriod {
		return fmt.Errorf("leaseDuration must exceed renewDeadline plus fenceTimeout plus retryPeriod")
	}
	names := map[string]bool{}
	for _, name := range l.RequireReadyContainers {
		if len(validation.IsDNS1123Label(name)) != 0 || names[name] {
			return fmt.Errorf("required ready container names must be valid and unique")
		}
		names[name] = true
	}
	ports := map[int]bool{}
	for _, n := range c.Interfaces {
		if n.ListenPort <= 0 || n.ListenPort > 65535 || n.ListenPort == 500 || n.ListenPort == 4500 || ports[n.ListenPort] {
			return fmt.Errorf("activation requires fixed, unique positive WireGuard listen ports")
		}
		ports[n.ListenPort] = true
	}
	return nil
}
