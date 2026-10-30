package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantdomain"
)

// Domain statuses.
const (
	StatusPendingDNS = "pending_dns"
	StatusIssuing    = "issuing"
	StatusActive     = "active"
	StatusFailed     = "failed"
	StatusRemoving   = "removing"
)

var (
	ErrInvalidHostname = errors.New("enter a hostname such as shop.example.co.ke")
	ErrReservedHost    = errors.New("platform hostnames cannot be added as tenant domains")
	ErrUnknownService  = errors.New("unknown service")
	ErrHostTaken       = errors.New("this hostname is already connected")
	ErrUnavailable     = errors.New("custom domains are not set up on this platform yet")
	ErrNotFound        = errors.New("domain not found")
)

// reservedSuffixes are platform zones a tenant can never claim.
var reservedSuffixes = []string{"codevertexafrica.com", "codevertexitsolutions.com", "masterspace.co.ke", "kura.go.ke"}

var hostnameRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// NormaliseHostname lower-cases, strips a scheme, path and port, and validates the result.
func NormaliseHostname(raw string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	h = strings.TrimSuffix(h, ".")
	if len(h) > 253 || !hostnameRE.MatchString(h) || net.ParseIP(h) != nil {
		return "", ErrInvalidHostname
	}
	for _, s := range reservedSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return "", ErrReservedHost
		}
	}
	return h, nil
}

// Domain is the API view of a tenant domain, including the DNS record to add for external DNS.
type Domain struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Service     string     `json:"service"`
	ServiceName string     `json:"service_name"`
	Hostname    string     `json:"hostname"`
	Status      string     `json:"status"`
	DNSMode     string     `json:"dns_mode"`
	DNSRecord   *DNSRecord `json:"dns_record,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CheckedAt   *time.Time `json:"last_checked_at,omitempty"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	URL         string     `json:"url"`
}

// DNSRecord is the record a tenant adds at their own DNS provider.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Resolution maps a request host to the tenant and service it serves.
type Resolution struct {
	Hostname   string    `json:"hostname"`
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantSlug string    `json:"tenant_slug"`
	Service    string    `json:"service"`
	Status     string    `json:"status"`
}

// Service manages tenant domains.
type Service struct {
	ent      *ent.Client
	log      *zap.Logger
	originIP string
	cf       *cloudflare
	k8s      *cluster

	cacheMu sync.Mutex
	cache   map[string]cachedResolution
	hostsAt time.Time
	hosts   []string
}

type cachedResolution struct {
	res *Resolution
	at  time.Time
}

const resolveTTL = 60 * time.Second

// New builds the service. Outside the cluster (or without an origin IP) it still lists and
// stores domains, but the reconciler cannot connect them and says so.
func New(client *ent.Client, log *zap.Logger, cfToken, originIP, issuer string) *Service {
	s := &Service{ent: client, log: log.Named("domains"), originIP: strings.TrimSpace(originIP),
		cf: newCloudflare(cfToken), cache: map[string]cachedResolution{}}
	if k, err := newCluster(issuer); err == nil {
		s.k8s = k
	} else {
		s.log.Info("tenant domains: not running in a cluster, reconciler disabled", zap.Error(err))
	}
	return s
}

// Enabled reports whether domains can actually be connected here.
func (s *Service) Enabled() bool { return s.originIP != "" && s.k8s != nil }

func (s *Service) view(d *ent.TenantDomain) Domain {
	t, _ := Target(d.Service)
	v := Domain{ID: d.ID, TenantID: d.TenantID, Service: d.Service, ServiceName: t.Name, Hostname: d.Hostname,
		Status: d.Status, DNSMode: d.DNSMode, LastError: d.LastError, CheckedAt: d.LastCheckedAt,
		ActivatedAt: d.ActivatedAt, CreatedAt: d.CreatedAt, URL: "https://" + d.Hostname}
	if d.DNSMode == "external" && s.originIP != "" && d.Status != StatusActive {
		v.DNSRecord = &DNSRecord{Type: "A", Name: d.Hostname, Value: s.originIP}
	}
	return v
}

// List returns a tenant's domains, newest first.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Domain, error) {
	rows, err := s.ent.TenantDomain.Query().Where(tenantdomain.TenantID(tenantID)).
		Order(ent.Desc(tenantdomain.FieldCreatedAt)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.view(r))
	}
	return out, nil
}

// Create adds a domain for a tenant and kicks the first reconcile step.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, rawHost, service, createdBy string) (Domain, error) {
	if !s.Enabled() {
		return Domain{}, ErrUnavailable
	}
	host, err := NormaliseHostname(rawHost)
	if err != nil {
		return Domain{}, err
	}
	if _, ok := Target(service); !ok {
		return Domain{}, ErrUnknownService
	}
	mode := "external"
	zoneID := ""
	if s.cf != nil {
		if id, _, zErr := s.cf.zoneFor(ctx, host); zErr == nil && id != "" {
			mode, zoneID = "cloudflare", id
		} else if zErr != nil {
			s.log.Warn("tenant domains: cloudflare zone lookup failed, using external DNS", zap.Error(zErr))
		}
	}
	row, err := s.ent.TenantDomain.Create().SetTenantID(tenantID).SetService(service).SetHostname(host).
		SetStatus(StatusPendingDNS).SetDNSMode(mode).SetCfZoneID(zoneID).SetCreatedBy(createdBy).Save(ctx)
	if ent.IsConstraintError(err) {
		return Domain{}, ErrHostTaken
	}
	if err != nil {
		return Domain{}, err
	}
	row = s.step(ctx, row)
	return s.view(row), nil
}

func (s *Service) get(ctx context.Context, tenantID, id uuid.UUID) (*ent.TenantDomain, error) {
	row, err := s.ent.TenantDomain.Query().Where(tenantdomain.ID(id), tenantdomain.TenantID(tenantID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	return row, err
}

// Recheck runs one reconcile step now (the "Check again" button).
func (s *Service) Recheck(ctx context.Context, tenantID, id uuid.UUID) (Domain, error) {
	row, err := s.get(ctx, tenantID, id)
	if err != nil {
		return Domain{}, err
	}
	return s.view(s.step(ctx, row)), nil
}

// Remove disconnects a domain: the reconciler removes its Ingress, our DNS record and its OAuth
// redirects, then the row.
func (s *Service) Remove(ctx context.Context, tenantID, id uuid.UUID) error {
	row, err := s.get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	row, err = row.Update().SetStatus(StatusRemoving).Save(ctx)
	if err != nil {
		return err
	}
	s.forget(row.Hostname)
	s.step(ctx, row)
	return nil
}

// Resolve maps a host to its tenant and service (active or issuing domains), cached briefly.
func (s *Service) Resolve(ctx context.Context, rawHost string) (*Resolution, error) {
	host, err := NormaliseHostname(rawHost)
	if err != nil {
		return nil, nil
	}
	s.cacheMu.Lock()
	if c, ok := s.cache[host]; ok && time.Since(c.at) < resolveTTL {
		s.cacheMu.Unlock()
		return c.res, nil
	}
	s.cacheMu.Unlock()
	row, err := s.ent.TenantDomain.Query().Where(tenantdomain.Hostname(host),
		tenantdomain.StatusIn(StatusActive, StatusIssuing)).Only(ctx)
	var res *Resolution
	switch {
	case ent.IsNotFound(err):
	case err != nil:
		return nil, err
	default:
		tn, tErr := s.ent.Tenant.Query().Where(tenant.ID(row.TenantID)).Only(ctx)
		if tErr != nil {
			return nil, tErr
		}
		res = &Resolution{Hostname: host, TenantID: row.TenantID, TenantSlug: tn.Slug, Service: row.Service, Status: row.Status}
	}
	s.cacheMu.Lock()
	s.cache[host] = cachedResolution{res: res, at: time.Now()}
	s.cacheMu.Unlock()
	return res, nil
}

func (s *Service) forget(host string) {
	s.cacheMu.Lock()
	delete(s.cache, host)
	s.hosts = nil
	s.cacheMu.Unlock()
}

// ActiveHosts lists hostnames of active domains (sign-in return and logout trust), cached.
func (s *Service) ActiveHosts(ctx context.Context) []string {
	s.cacheMu.Lock()
	if s.hosts != nil && time.Since(s.hostsAt) < resolveTTL {
		h := s.hosts
		s.cacheMu.Unlock()
		return h
	}
	s.cacheMu.Unlock()
	rows, err := s.ent.TenantDomain.Query().Where(tenantdomain.Status(StatusActive)).
		Select(tenantdomain.FieldHostname).Strings(ctx)
	if err != nil {
		s.log.Warn("tenant domains: active hosts", zap.Error(err))
		return nil
	}
	s.cacheMu.Lock()
	s.hosts, s.hostsAt = rows, time.Now()
	s.cacheMu.Unlock()
	return rows
}

// Reconcile advances every domain that is not settled. Called on a timer under a cluster-wide
// lock, so only one replica does it.
func (s *Service) Reconcile(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	rows, err := s.ent.TenantDomain.Query().Where(tenantdomain.StatusIn(StatusPendingDNS, StatusIssuing, StatusFailed, StatusRemoving)).
		Limit(200).All(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		s.step(ctx, r)
	}
	return nil
}

// step moves one domain forward and records the outcome on the row.
func (s *Service) step(ctx context.Context, row *ent.TenantDomain) *ent.TenantDomain {
	t, ok := Target(row.Service)
	if !ok || !s.Enabled() {
		return row
	}
	now := time.Now()
	upd := row.Update().SetLastCheckedAt(now)
	set := func(status, msg string) {
		upd = upd.SetStatus(status)
		if msg == "" {
			upd = upd.ClearLastError()
		} else {
			upd = upd.SetLastError(msg)
		}
	}

	switch row.Status {
	case StatusRemoving:
		if err := s.k8s.deleteIngress(ctx, row.Hostname, t); err != nil {
			set(StatusRemoving, "could not remove the ingress: "+err.Error())
			break
		}
		if row.DNSMode == "cloudflare" && s.cf != nil {
			if err := s.cf.deleteRecord(ctx, row.CfZoneID, row.CfRecordID); err != nil {
				set(StatusRemoving, "could not remove the DNS record: "+err.Error())
				break
			}
		}
		if err := s.setRedirects(ctx, row.Hostname, t, false); err != nil {
			set(StatusRemoving, "could not remove sign-in redirects: "+err.Error())
			break
		}
		if err := s.ent.TenantDomain.DeleteOne(row).Exec(ctx); err != nil {
			s.log.Warn("tenant domains: delete row", zap.String("host", row.Hostname), zap.Error(err))
		}
		s.forget(row.Hostname)
		return row

	case StatusPendingDNS, StatusFailed:
		if row.DNSMode == "cloudflare" && s.cf != nil {
			id, err := s.cf.upsertA(ctx, row.CfZoneID, row.Hostname, s.originIP)
			if err != nil {
				set(StatusPendingDNS, err.Error())
				break
			}
			upd = upd.SetCfRecordID(id)
		} else if !s.pointsHere(row.Hostname) {
			set(StatusPendingDNS, fmt.Sprintf("waiting for %s to point at the platform (A record %s)", row.Hostname, s.originIP))
			break
		}
		if err := s.k8s.ensureIngress(ctx, row.Hostname, t); err != nil {
			set(StatusFailed, "could not create the ingress: "+err.Error())
			break
		}
		set(StatusIssuing, "")
		fallthrough

	case StatusIssuing, StatusActive:
		if row.Status == StatusActive {
			// Keep an active domain's ingress in place (it may have been removed by hand).
			if err := s.k8s.ensureIngress(ctx, row.Hostname, t); err != nil {
				set(StatusActive, "ingress check failed: "+err.Error())
				break
			}
		}
		ready, msg, err := s.k8s.certificateReady(ctx, row.Hostname, t)
		if err != nil {
			set(StatusIssuing, "could not read the certificate: "+err.Error())
			break
		}
		if !ready {
			set(StatusIssuing, msg)
			break
		}
		if err := s.setRedirects(ctx, row.Hostname, t, true); err != nil {
			set(StatusIssuing, "could not add sign-in redirects: "+err.Error())
			break
		}
		set(StatusActive, "")
		if row.ActivatedAt == nil {
			upd = upd.SetActivatedAt(now)
		}
		s.forget(row.Hostname)
	}

	saved, err := upd.Save(ctx)
	if err != nil {
		s.log.Warn("tenant domains: save step", zap.String("host", row.Hostname), zap.Error(err))
		return row
	}
	return saved
}

// pointsHere reports whether public DNS already resolves host to the platform origin.
func (s *Service) pointsHere(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && slices.Contains(addrs, s.originIP)
}

// redirectURIs are the sign-in callbacks for a host: the root one, plus one per tenant slug when
// the app routes tenants by path (mirrors cmd/seed buildRedirects).
func (s *Service) redirectURIs(ctx context.Context, host string, t ServiceTarget) ([]string, error) {
	uris := []string{"https://" + host + "/auth/callback"}
	if t.TenantPath {
		slugs, err := s.ent.Tenant.Query().Select(tenant.FieldSlug).Strings(ctx)
		if err != nil {
			return nil, err
		}
		for _, slug := range slugs {
			uris = append(uris, "https://"+host+"/"+slug+"/auth/callback")
		}
	}
	return uris, nil
}

// setRedirects adds (or removes) the host's callbacks on the service's OAuth client.
func (s *Service) setRedirects(ctx context.Context, host string, t ServiceTarget, add bool) error {
	if t.OAuthClientID == "" {
		return nil
	}
	client, err := s.ent.OAuthClient.Query().Where(oauthclient.ClientID(t.OAuthClientID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	prefix := "https://" + host + "/"
	kept := make([]string, 0, len(client.RedirectUris))
	for _, u := range client.RedirectUris {
		if !strings.HasPrefix(u, prefix) {
			kept = append(kept, u)
		}
	}
	if add {
		extra, err := s.redirectURIs(ctx, host, t)
		if err != nil {
			return err
		}
		kept = append(kept, extra...)
	}
	if slices.Equal(kept, client.RedirectUris) {
		return nil
	}
	return client.Update().SetRedirectUris(kept).Exec(ctx)
}
