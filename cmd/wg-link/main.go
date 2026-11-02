package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	_, e := link.Load(*config)
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
			var rc *rest.Config
			var e error
			if *kubeconfig != "" {
				rc, e = clientcmd.BuildConfigFromFlags("", *kubeconfig)
			} else {
				rc, e = rest.InClusterConfig()
			}
			if e != nil {
				return e
			}
			client, e := kubernetes.NewForConfig(rc)
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
	go a.Run(ctx, *config, events, func(err error) {
		log.Printf("reconciliation failed: %v", err)
	})
	select {
	case <-ctx.Done():
	case e = <-errors:
		cancel()
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	return e
}
