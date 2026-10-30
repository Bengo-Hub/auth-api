// Package domains connects tenants' own hostnames to platform services, Vercel style: a tenant (or
// a platform admin for them) adds "shop.example.co.ke" for the ordering storefront, and the
// reconciler creates the DNS record when the zone is in our Cloudflare account, the Kubernetes
// Ingress with a cert-manager certificate, and the service's OAuth redirect URIs, then marks the
// domain active once the certificate is ready. Frontends map a host to its tenant through Resolve.
package domains

import "sort"

// ServiceTarget is where a tenant hostname for one platform service is routed in the cluster.
type ServiceTarget struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Namespace string `json:"-"`
	Service   string `json:"-"`
	Port      int32  `json:"-"`
	// OAuthClientID gets the domain's sign-in callbacks added to its redirect URIs.
	OAuthClientID string `json:"-"`
	// TenantPath: the app routes tenants by a leading "/{slug}" path segment, so a callback
	// exists per tenant slug as well as at the root.
	TenantPath bool `json:"-"`
}

// catalogue lists the services a tenant can put on its own domain. Facts come from the cluster
// (namespace, Service name, port) and auth-api's seeded OAuth clients.
var catalogue = map[string]ServiceTarget{
	"ordering":   {Key: "ordering", Name: "Online store and ordering", Namespace: "ordering", Service: "ordering-frontend", Port: 80, OAuthClientID: "ordering-ui", TenantPath: true},
	"truload":    {Key: "truload", Name: "TruLoad weighing", Namespace: "truload", Service: "truload-frontend-app", Port: 80, OAuthClientID: "truload-ui", TenantPath: true},
	"erp":        {Key: "erp", Name: "ERP", Namespace: "erp", Service: "erp-ui", Port: 80, OAuthClientID: "erp-ui", TenantPath: true},
	"pos":        {Key: "pos", Name: "Point of sale", Namespace: "pos", Service: "pos-ui", Port: 80, OAuthClientID: "pos-ui", TenantPath: true},
	"inventory":  {Key: "inventory", Name: "Inventory", Namespace: "inventory", Service: "inventory-ui", Port: 80, OAuthClientID: "inventory-ui", TenantPath: true},
	"logistics":  {Key: "logistics", Name: "Logistics", Namespace: "logistics", Service: "logistics-ui", Port: 80, OAuthClientID: "logistics-ui", TenantPath: true},
	"marketflow": {Key: "marketflow", Name: "MarketFlow", Namespace: "marketflow", Service: "marketflow-ui", Port: 3000, OAuthClientID: "marketflow-ui", TenantPath: true},
	"ticketing":  {Key: "ticketing", Name: "Ticketing", Namespace: "ticketing", Service: "ticketing-ui", Port: 80, OAuthClientID: "ticketing-ui", TenantPath: true},
}

// Target returns the routing target for a service key.
func Target(key string) (ServiceTarget, bool) {
	t, ok := catalogue[key]
	return t, ok
}

// Services lists the catalogue for pickers, by name.
func Services() []ServiceTarget {
	out := make([]ServiceTarget, 0, len(catalogue))
	for _, t := range catalogue {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Namespaces lists the namespaces the reconciler writes Ingress objects in (the RBAC scope).
func Namespaces() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range catalogue {
		if !seen[t.Namespace] {
			seen[t.Namespace] = true
			out = append(out, t.Namespace)
		}
	}
	sort.Strings(out)
	return out
}
