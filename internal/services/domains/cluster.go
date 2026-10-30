package domains

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// cluster writes one Ingress per tenant domain in the service's namespace. cert-manager's
// ingress-shim then issues the certificate named after the TLS secret. RBAC (devops-k8s
// manifests/auth-api-domains-rbac.yaml) allows only ingresses and certificate reads in the
// catalogue namespaces.
type cluster struct {
	core   kubernetes.Interface
	dyn    dynamic.Interface
	issuer string
}

var certificateGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}

// managedLabel marks objects this package owns, so nothing else is ever touched or deleted.
const managedLabel = "codevertex.io/tenant-domain"

func newCluster(issuer string) (*cluster, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	cfg.Timeout = 20 * time.Second
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &cluster{core: core, dyn: dyn, issuer: issuer}, nil
}

var nonName = regexp.MustCompile(`[^a-z0-9-]+`)

// objectName is a stable, valid Kubernetes name for a hostname: "td-" plus a readable prefix and
// a short hash, so long or similar hostnames never collide.
func objectName(host string) string {
	sum := sha256.Sum256([]byte(host))
	base := strings.Trim(nonName.ReplaceAllString(strings.ReplaceAll(host, ".", "-"), "-"), "-")
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	return "td-" + base + "-" + hex.EncodeToString(sum[:])[:8]
}

// ensureIngress creates or updates the domain's Ingress.
func (c *cluster) ensureIngress(ctx context.Context, host string, t ServiceTarget) error {
	name := objectName(host)
	pathType := networkingv1.PathTypePrefix
	class := "nginx"
	desired := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: t.Namespace,
			Labels:    map[string]string{managedLabel: "true", "app.kubernetes.io/managed-by": "auth-api-domains"},
			Annotations: map[string]string{
				"cert-manager.io/cluster-issuer":                 c.issuer,
				"nginx.ingress.kubernetes.io/ssl-redirect":       "true",
				"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
				"codevertex.io/tenant-domain-host":               host,
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &class,
			TLS:              []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: name + "-tls"}},
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Path: "/", PathType: &pathType,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: t.Service, Port: networkingv1.ServiceBackendPort{Number: t.Port},
						}},
					}},
				}},
			}},
		},
	}
	api := c.core.NetworkingV1().Ingresses(t.Namespace)
	current, err := api.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = api.Create(ctx, desired, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if current.Labels[managedLabel] != "true" {
		return fmt.Errorf("ingress %s/%s exists and is not managed by tenant domains", t.Namespace, name)
	}
	desired.ResourceVersion = current.ResourceVersion
	_, err = api.Update(ctx, desired, metav1.UpdateOptions{})
	return err
}

// certificateReady reports whether cert-manager has issued the domain's certificate, and the
// latest condition message while it has not.
func (c *cluster) certificateReady(ctx context.Context, host string, t ServiceTarget) (bool, string, error) {
	obj, err := c.dyn.Resource(certificateGVR).Namespace(t.Namespace).Get(ctx, objectName(host)+"-tls", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, "waiting for the certificate request", nil
	}
	if err != nil {
		return false, "", err
	}
	conds, _, _ := unstructuredSlice(obj.Object, "status", "conditions")
	for _, raw := range conds {
		cond, _ := raw.(map[string]any)
		if cond["type"] == "Ready" {
			msg, _ := cond["message"].(string)
			return cond["status"] == "True", msg, nil
		}
	}
	return false, "certificate is being issued", nil
}

func unstructuredSlice(obj map[string]any, path ...string) ([]any, bool, error) {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false, nil
		}
		cur = m[p]
	}
	s, ok := cur.([]any)
	return s, ok, nil
}

// deleteIngress removes the domain's Ingress (cert-manager then cleans up its Certificate; the
// TLS secret is left to expire unused). Already gone is not an error.
func (c *cluster) deleteIngress(ctx context.Context, host string, t ServiceTarget) error {
	api := c.core.NetworkingV1().Ingresses(t.Namespace)
	current, err := api.Get(ctx, objectName(host), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Labels[managedLabel] != "true" {
		return nil
	}
	err = api.Delete(ctx, current.Name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
