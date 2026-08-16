// Package k8s provides read-only access to the live Kubernetes cluster for
// the platform infrastructure monitoring dashboard (replaces the removed
// Prometheus/Grafana stack). The bound ServiceAccount (auth-api-monitor,
// see devops-k8s/manifests/auth-api-monitor-rbac.yaml) only has get/list/watch
// RBAC — this package never issues a write call.
package k8s

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

// Client wraps the clientsets needed by Overview.
type Client struct {
	core    kubernetes.Interface
	metrics metricsv.Interface

	// dependencyPingers are optional, app-supplied health checks for things
	// k8s pod state can't see (e.g. "is my Redis connection actually alive").
	// Kept as plain closures rather than importing e.g. go-redis directly, so
	// this package stays dependency-agnostic. Populated via SetDependencyPing.
	dependencyPingers []dependencyPinger
}

type dependencyPinger struct {
	name string
	ping func(ctx context.Context) error
}

// SetDependencyPing registers a named health check to be run on every
// Overview() call and surfaced as DependencyHealth. Safe to call multiple
// times to register several dependencies (e.g. Redis, a downstream API).
func (c *Client) SetDependencyPing(name string, ping func(ctx context.Context) error) {
	c.dependencyPingers = append(c.dependencyPingers, dependencyPinger{name: name, ping: ping})
}

// NewInClusterClient builds a Client from the pod's mounted ServiceAccount
// token. It returns an error when not running inside a cluster (e.g. local
// dev) so callers can degrade gracefully instead of failing startup.
func NewInClusterClient() (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	cfg.Timeout = 15 * time.Second

	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	metrics, err := metricsv.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{core: core, metrics: metrics}, nil
}
