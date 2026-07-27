// Package k8s provides read-only access to the live Kubernetes cluster for
// the platform infrastructure monitoring dashboard (replaces the removed
// Prometheus/Grafana stack). The bound ServiceAccount (auth-api-monitor,
// see devops-k8s/manifests/auth-api-monitor-rbac.yaml) only has get/list/watch
// RBAC — this package never issues a write call.
package k8s

import (
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

// Client wraps the clientsets needed by Overview.
type Client struct {
	core    kubernetes.Interface
	metrics metricsv.Interface
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
