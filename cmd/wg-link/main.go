package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	link "github.com/brick4u/wg-link"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	config := flag.String("config", "/etc/wg-link/config.yaml", "configuration file")
	listen := flag.String("listen", ":9090", "health and metrics address")
	kubeconfig := flag.String("kubeconfig", "", "optional kubeconfig; otherwise in-cluster")
	check := flag.Bool("check", false, "validate config and keys without kernel or API access")
	flag.Parse()
	initial, e := link.Load(*config)
	if e != nil {
		return e
	}
	if *check {
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	b, e := link.NewLinuxBackend()
	if e != nil {
		return e
	}
	defer b.Close()
	a := &link.Agent{Backend: b}
	events := make(chan struct{}, 1)
	notify := func() {
		select {
		case events <- struct{}{}:
		default:
		}
	}
	var client kubernetes.Interface
	getClient := func() (kubernetes.Interface, error) {
		if client != nil {
			return client, nil
		}
		var rc *rest.Config
		var err error
		if *kubeconfig != "" {
			rc, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		} else {
			rc, err = rest.InClusterConfig()
		}
		if err != nil {
			return nil, err
		}
		rc.Timeout = 3 * time.Second
		client, err = kubernetes.NewForConfig(rc)
		return client, err
	}
	var activation *link.Activation
	var activationDone chan error
	var activationCancel context.CancelFunc
	if initial.Activation != nil {
		client, err := getClient()
		if err != nil {
			return err
		}
		ports := []int{}
		for _, n := range initial.Interfaces {
			ports = append(ports, n.ListenPort)
		}
		guard, err := link.NewHAGuardWithTimeout(ports, initial.Activation.FenceTimeout)
		if err != nil {
			return err
		}
		if err = guard.InstallClosed(ctx); err != nil {
			return err
		}
		identity := link.PodIdentity{Namespace: os.Getenv("POD_NAMESPACE"), Name: os.Getenv("POD_NAME"), UID: os.Getenv("POD_UID"), ContainerName: os.Getenv("WG_CONTAINER_NAME")}
		activation, err = link.NewActivation(client, *initial.Activation, identity, guard, notify)
		if err != nil {
			return err
		}
		a.Activation = activation
		a.ValidateRuntime = func(next *link.Config) error { return link.ValidateActivationReload(initial, next) }
		activationCtx, stop := context.WithCancel(context.Background())
		activationCancel = stop
		activationDone = make(chan error, 1)
		go func() { activationDone <- activation.Run(activationCtx) }()
	}
	var discovery *link.Discovery
	a.Prepare = func(c *link.Config) error {
		namespaces := []string{}
		for _, n := range c.Interfaces {
			for _, p := range n.Peers {
				if p.Service != nil {
					namespaces = append(namespaces, p.Service.Namespace)
				}
			}
		}
		if len(namespaces) > 0 {
			if discovery != nil {
				discovery.EnsureNamespaces(namespaces)
				return nil
			}
			client, e := getClient()
			if e != nil {
				return e
			}
			discovery = link.NewDiscovery(ctx, client, namespaces, notify)
			a.Discovery = discovery
		}
		return nil
	}
	server := &http.Server{Addr: *listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errors := make(chan error, 1)
	go func() { errors <- server.ListenAndServe() }()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		a.Run(ctx, *config, events, func(err error) { log.Printf("reconciliation failed: %v", err) })
	}()
	select {
	case <-ctx.Done():
	case e = <-errors:
		cancel()
	case e = <-activationDone:
		activationDone = nil
		cancel()
	}
	cancel()
	// Stop reconciliation before activation closes the gate and releases ownership.
	workers.Wait()
	if activationCancel != nil {
		activationCancel()
	}
	if activationDone != nil {
		if err := <-activationDone; err != nil && e == nil {
			e = err
		}
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	return e
}
