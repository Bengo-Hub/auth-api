// Package tenantbackup builds a tenant's backup from the SSO client area: one export per service
// (each service streams its tenant rows through httpware/tenantexport), packed into one zip on the
// private object storage. Backups run on demand only (the platform pg_dumpall covers disaster
// recovery), only the newest is kept per tenant, and tenants download it through a presigned link.
//
// Which services are collected is decided per tenant, never globally:
//   - a service the tenant's plan does not cover (subscriptions-api entitled-services) is skipped
//     and reported as not_in_plan; if the plan cannot be verified the backup does not start;
//   - the tenant may pick a subset of the services its plan covers;
//   - a covered service is probed first and skipped as empty when the tenant has no rows in it.
//
// The state lives in tenants.metadata.backup, written with jsonb_set so other metadata writes are
// never overwritten.
package tenantbackup

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bengo-Hub/httpware/objectstore"
	"github.com/Bengo-Hub/httpware/tenantexport"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/clients/subscription"
)

// Status values of a tenant backup.
const (
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// Result values of one service inside a backup.
const (
	ResultOK          = "ok"          // exported and archived
	ResultEmpty       = "empty"       // the tenant has no rows in the service
	ResultNotInPlan   = "not_in_plan" // the tenant's plan does not cover the service
	ResultUnavailable = "unavailable" // the service has no export endpoint
	ResultFailed      = "failed"
)

const (
	exportPath = "/api/v1/s2s/tenant-export"
	// staleAfter lets a new backup start when a run stopped reporting (its pod restarted).
	staleAfter = 15 * time.Minute
	// heartbeatEvery keeps a long single-service stream from looking abandoned.
	heartbeatEvery = 30 * time.Second
	// jobTimeout bounds one backup run; serviceTimeout bounds one service so a hung service cannot
	// hold the others; probeTimeout bounds the "has data" check.
	jobTimeout     = 45 * time.Minute
	serviceTimeout = 20 * time.Minute
	probeTimeout   = 15 * time.Second
	// maxParallel services are exported at once.
	maxParallel = 3
	// maxArchiveBytes caps one archive (the backups object type allows 2 GiB).
	maxArchiveBytes int64 = 2 << 30
)

var (
	// ErrRunning is returned when a backup of the tenant is already in progress.
	ErrRunning = errors.New("a backup of this tenant is already running")
	// ErrUnknownService is returned when a requested service is not one this backup collects.
	ErrUnknownService = errors.New("unknown service")
	// ErrNotInPlan is returned when a requested service is not covered by the tenant's plan.
	ErrNotInPlan = errors.New("service is not in the tenant's plan")
	// ErrNothingToBackup is returned when no service is eligible.
	ErrNothingToBackup = errors.New("no service to back up")
	// ErrPlanUnverified is returned when the tenant's plan could not be read; a backup never guesses.
	ErrPlanUnverified = errors.New("the tenant's plan could not be verified")
)

// Entitler tells which billable services a tenant's plan covers (subscriptions-api).
type Entitler interface {
	GetEntitledServices(ctx context.Context, tenantID uuid.UUID) (*subscription.EntitledServices, error)
}

// Target is one service a backup can collect from.
type Target struct {
	URL string
	// Tag is the billable service tag its data belongs to. Empty for platform services
	// (notifications, subscriptions) that every tenant has and no plan sells.
	Tag string
}

// platformServices have no plan; their tag stays empty unless set explicitly.
var platformServices = map[string]bool{"auth": true, "notifications": true, "subscriptions": true}

// ServiceResult is one service's part of a backup.
type ServiceResult struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Bytes   int64  `json:"bytes,omitempty"`
	Rows    int64  `json:"rows,omitempty"`
	Error   string `json:"error,omitempty"`
}

// State is tenants.metadata.backup.
type State struct {
	Status      string          `json:"status"`
	Key         string          `json:"key,omitempty"` // newest completed archive
	Size        int64           `json:"size,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	HeartbeatAt time.Time       `json:"heartbeat_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	RequestedBy string          `json:"requested_by,omitempty"`
	Selected    []string        `json:"selected,omitempty"` // services the tenant picked (empty = all in plan)
	Services    []ServiceResult `json:"services,omitempty"`
	Partial     bool            `json:"partial,omitempty"` // finished, but some service failed
	Error       string          `json:"error,omitempty"`
}

// CatalogEntry is one service the tenant can choose in the backup picker.
type CatalogEntry struct {
	Service  string `json:"service"`
	Name     string `json:"name"`
	Entitled bool   `json:"entitled"`
}

// Service runs tenant backups.
type Service struct {
	db       *sql.DB
	store    *objectstore.Store
	targets  map[string]Target
	entitler Entitler
	apiKey   string
	http     *http.Client
	log      *zap.Logger
	mu       sync.Mutex // serialises starts on this pod (the conditional UPDATE covers other pods)
}

// ParseServices reads "name=url" or "name=url|tag" entries separated by commas. The tag defaults
// to the service name (pos, erp, library, ...) except for platform services, which have none.
func ParseServices(raw string) map[string]Target {
	out := map[string]Target{}
	for _, part := range strings.Split(raw, ",") {
		name, rest, ok := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.TrimSpace(name)
		url, tag, hasTag := strings.Cut(strings.TrimSpace(rest), "|")
		url = strings.TrimRight(strings.TrimSpace(url), "/")
		if !ok || name == "" || url == "" {
			continue
		}
		tag = strings.TrimSpace(tag)
		if !hasTag && !platformServices[name] {
			tag = name
		}
		out[name] = Target{URL: url, Tag: tag}
	}
	return out
}

// New builds the service. store must be the auth object store (backups are private).
func New(db *sql.DB, store *objectstore.Store, targets map[string]Target, entitler Entitler, apiKey string, log *zap.Logger) *Service {
	return &Service{db: db, store: store, targets: targets, entitler: entitler, apiKey: apiKey,
		http: &http.Client{Timeout: 0}, log: log.Named("tenantbackup")}
}

// Enabled reports whether backups can run here.
func (s *Service) Enabled() bool {
	return s != nil && s.store.Enabled() && len(s.targets) > 0 && s.apiKey != "" && s.entitler != nil
}

// Get returns the tenant's backup state (nil when none was ever made).
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*State, error) {
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT metadata->'backup' FROM tenants WHERE id = $1`, tenantID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || !raw.Valid || raw.String == "null" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal([]byte(raw.String), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// DownloadURL is a short-lived link to the newest archive.
func (s *Service) DownloadURL(st *State, slug string) (string, error) {
	if st == nil || st.Key == "" {
		return "", objectstore.ErrNotFound
	}
	name := fmt.Sprintf("%s-backup-%s.zip", slug, completedOrStart(st).Format("20060102-1504"))
	return s.store.DownloadURL(st.Key, name, 15*time.Minute)
}

func completedOrStart(st *State) time.Time {
	if st.CompletedAt != nil {
		return *st.CompletedAt
	}
	return st.StartedAt
}

// plan is the tenant's entitlement snapshot for one backup decision.
type plan struct {
	exempt bool
	tags   map[string]bool
	names  map[string]string
}

func (p *plan) covers(tag string) bool { return tag == "" || p.exempt || p.tags[tag] }

func (s *Service) plan(ctx context.Context, tenantID uuid.UUID) (*plan, error) {
	if s.entitler == nil {
		return nil, ErrPlanUnverified
	}
	es, err := s.entitler.GetEntitledServices(ctx, tenantID)
	if err != nil || es == nil {
		s.log.Warn("tenant plan not verified", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil, ErrPlanUnverified
	}
	p := &plan{exempt: es.Exempt, tags: map[string]bool{}, names: map[string]string{}}
	for _, e := range es.Services {
		p.names[e.ServiceTag] = e.Name
		if e.Entitled {
			p.tags[e.ServiceTag] = true
		}
	}
	return p, nil
}

func (s *Service) sortedNames() []string {
	names := make([]string, 0, len(s.targets))
	for n := range s.targets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var displayNames = map[string]string{
	"erp": "ERP", "pos": "POS", "ordering": "Ordering", "inventory": "Inventory", "treasury": "Treasury",
	"logistics": "Logistics", "marketflow": "Marketflow", "hospital": "Hospital", "library": "Library",
	"maskani": "Maskani", "projects": "Projects", "notifications": "Notifications", "subscriptions": "Subscriptions",
}

func (s *Service) displayName(p *plan, name string) string {
	if n := p.names[s.targets[name].Tag]; n != "" {
		return n
	}
	if n := displayNames[name]; n != "" {
		return n
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

// Catalog lists the services a backup can collect with whether the tenant's plan covers each, for
// the picker. It errors with ErrPlanUnverified when the plan cannot be read.
func (s *Service) Catalog(ctx context.Context, tenantID uuid.UUID) ([]CatalogEntry, error) {
	p, err := s.plan(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]CatalogEntry, 0, len(s.targets))
	for _, name := range s.sortedNames() {
		out = append(out, CatalogEntry{Service: name, Name: s.displayName(p, name), Entitled: p.covers(s.targets[name].Tag)})
	}
	return out, nil
}

// resolve turns the tenant's selection into the services to collect (eligible) and, when nothing
// was selected, the services outside the plan to report as not_in_plan (skipped).
func (s *Service) resolve(selected []string, p *plan) (eligible []string, skipped []ServiceResult, err error) {
	if len(selected) == 0 {
		for _, name := range s.sortedNames() {
			if p.covers(s.targets[name].Tag) {
				eligible = append(eligible, name)
			} else {
				skipped = append(skipped, ServiceResult{Service: name, Status: ResultNotInPlan})
			}
		}
	} else {
		seen := map[string]bool{}
		for _, name := range selected {
			name = strings.TrimSpace(name)
			t, ok := s.targets[name]
			switch {
			case !ok:
				return nil, nil, fmt.Errorf("%w: %s", ErrUnknownService, name)
			case !p.covers(t.Tag):
				return nil, nil, fmt.Errorf("%w: %s", ErrNotInPlan, name)
			case seen[name]:
				continue
			}
			seen[name] = true
			eligible = append(eligible, name)
		}
		sort.Strings(eligible)
	}
	if len(eligible) == 0 {
		return nil, nil, ErrNothingToBackup
	}
	return eligible, skipped, nil
}

// Start begins a backup in the background and returns its initial state. selected lists the
// services to collect (empty = every service in the tenant's plan). Only one backup per tenant
// runs at a time across all pods; a run that stopped reporting for 15 minutes counts as abandoned.
func (s *Service) Start(ctx context.Context, tenantID uuid.UUID, requestedBy string, selected []string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.plan(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	eligible, skipped, err := s.resolve(selected, p)
	if err != nil {
		return nil, err
	}
	prev, err := s.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	st := &State{Status: StatusRunning, StartedAt: now, HeartbeatAt: now, RequestedBy: requestedBy,
		Selected: selected, Services: skipped}
	if prev != nil { // the previous archive stays downloadable until the new one completes
		st.Key, st.Size, st.CompletedAt = prev.Key, prev.Size, prev.CompletedAt
	}
	claimed, err := s.claim(ctx, tenantID, st)
	if err != nil {
		return nil, err
	}
	if !claimed {
		cur, _ := s.Get(ctx, tenantID)
		return cur, ErrRunning
	}
	go s.run(tenantID, st, prev, eligible)
	return st, nil
}

// claim stores the running state only when no fresh run exists, in one statement, so two pods
// cannot both start a backup for the same tenant.
func (s *Service) claim(ctx context.Context, tenantID uuid.UUID, st *State) (bool, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE tenants SET metadata = jsonb_set(coalesce(metadata, '{}'::jsonb), '{backup}', $1::jsonb, true)
		WHERE id = $2 AND (
			metadata->'backup' IS NULL
			OR metadata->'backup'->>'status' IS DISTINCT FROM 'running'
			OR (metadata->'backup'->>'heartbeat_at')::timestamptz < now() - make_interval(secs => $3))`,
		string(b), tenantID, staleAfter.Seconds())
	if err != nil {
		return false, fmt.Errorf("tenantbackup: claim: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Service) save(ctx context.Context, tenantID uuid.UUID, st *State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE tenants SET metadata = jsonb_set(coalesce(metadata, '{}'::jsonb), '{backup}', $1::jsonb, true) WHERE id = $2`,
		string(b), tenantID)
	if err != nil {
		return fmt.Errorf("tenantbackup: save state: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("tenantbackup: tenant %s not found", tenantID)
	}
	return nil
}

// runState guards the state shared by the export workers and the heartbeat.
type runState struct {
	s        *Service
	tenantID uuid.UUID
	mu       sync.Mutex
	st       *State
	done     bool
}

// persist applies mut and stores the state; the lock is held through the write so an older
// snapshot can never overwrite a newer one.
func (r *runState) persist(mut func(*State)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mut != nil {
		mut(r.st)
	}
	r.st.HeartbeatAt = time.Now().UTC()
	_ = r.s.save(context.Background(), r.tenantID, r.st)
}

func (r *runState) heartbeat(stop <-chan struct{}) {
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.mu.Lock()
			if !r.done {
				r.st.HeartbeatAt = time.Now().UTC()
				_ = r.s.save(context.Background(), r.tenantID, r.st)
			}
			r.mu.Unlock()
		}
	}
}

// part is one service's finished export waiting to be archived.
type part struct {
	res  ServiceResult
	path string // temp file holding the gzipped stream; empty when nothing is archived
}

func (s *Service) run(tenantID uuid.UUID, st *State, prev *State, eligible []string) {
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()
	log := s.log.With(zap.String("tenant_id", tenantID.String()))
	rs := &runState{s: s, tenantID: tenantID, st: st}
	stop := make(chan struct{})
	defer close(stop)
	go rs.heartbeat(stop)

	fail := func(err error) {
		log.Error("tenant backup failed", zap.Error(err))
		rs.persist(func(st *State) {
			st.Status, st.Error, rs.done = StatusFailed, err.Error(), true
			if prev != nil {
				st.Key, st.Size, st.CompletedAt = prev.Key, prev.Size, prev.CompletedAt
			}
		})
	}

	tmp, err := os.CreateTemp("", "tenant-backup-*.zip")
	if err != nil {
		fail(err)
		return
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	zw := zip.NewWriter(tmp)

	// Workers export up to maxParallel services at once; one consumer archives each finished part
	// and deletes its temp file at once, so disk use stays near the archive size.
	parts := make(chan part)
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, name := range eligible {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				parts <- part{res: ServiceResult{Service: name, Status: ResultFailed, Error: "backup stopped"}}
				return
			}
			parts <- s.fetch(ctx, tenantID, name, s.targets[name].URL)
		}(name)
	}
	go func() { wg.Wait(); close(parts) }()

	var abortErr error
	var written int64
	okCount, failCount := 0, 0
	for p := range parts {
		if p.path != "" {
			if abortErr == nil {
				if err := addPart(zw, p, &written); err != nil {
					abortErr = err
					cancel()
				}
			}
			_ = os.Remove(p.path)
		}
		switch p.res.Status {
		case ResultOK:
			okCount++
		case ResultFailed:
			failCount++
		}
		res := p.res
		rs.persist(func(st *State) { st.Services = append(st.Services, res) })
	}
	if abortErr != nil {
		fail(abortErr)
		return
	}
	if err := ctx.Err(); err != nil {
		fail(fmt.Errorf("backup timed out: %w", err))
		return
	}

	rs.mu.Lock()
	results := append([]ServiceResult(nil), st.Services...)
	rs.mu.Unlock()
	sort.Slice(results, func(i, j int) bool { return results[i].Service < results[j].Service })
	manifest, _ := json.MarshalIndent(map[string]any{
		"tenant_id": tenantID.String(), "generated_at": time.Now().UTC().Format(time.RFC3339),
		"services": results,
		"format":   "one <service>.jsonl.gz per service: gzipped JSON Lines (export, row..., summary)",
	}, "", "  ")
	if w, err := zw.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: time.Now()}); err == nil {
		_, _ = w.Write(manifest)
	}
	if err := zw.Close(); err != nil {
		fail(err)
		return
	}
	if okCount == 0 {
		if failCount > 0 {
			fail(errors.New("no service returned an export"))
		} else {
			fail(errors.New("there is no data to back up in the selected services"))
		}
		return
	}
	info, err := tmp.Stat()
	if err != nil {
		fail(err)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		fail(err)
		return
	}
	key, err := s.store.NewKey(objectstore.Owner{TenantID: tenantID.String()}, objectstore.TypeBackups, ".zip")
	if err != nil {
		fail(err)
		return
	}
	if err := s.store.PutStream(ctx, key, tmp, info.Size(), "application/zip"); err != nil {
		fail(err)
		return
	}
	done := time.Now().UTC()
	rs.persist(func(st *State) {
		st.Status, st.Key, st.Size, st.CompletedAt, st.Error = StatusCompleted, key, info.Size(), &done, ""
		st.Partial = failCount > 0
		rs.done = true
	})
	// Only the newest backup is kept.
	if prev != nil && prev.Key != "" && prev.Key != key && s.store.Owned(prev.Key) {
		if err := s.store.Delete(context.Background(), prev.Key); err != nil {
			log.Warn("previous tenant backup not deleted", zap.String("key", prev.Key), zap.Error(err))
		}
	}
	log.Info("tenant backup completed", zap.Int64("bytes", info.Size()), zap.Int("services", okCount), zap.Int("failed", failCount))
}

var errTooLarge = errors.New("the backup is larger than the 2 GB limit; pick fewer services")

// addPart stores one service's stream as its own zip entry (already gzipped, so stored as is).
func addPart(zw *zip.Writer, p part, written *int64) error {
	if *written+p.res.Bytes > maxArchiveBytes {
		return errTooLarge
	}
	f, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := zw.CreateHeader(&zip.FileHeader{Name: p.res.Service + ".jsonl.gz", Method: zip.Store, Modified: time.Now()})
	if err != nil {
		return err
	}
	n, err := io.Copy(w, f)
	*written += n
	return err
}

type probeOutcome int

const (
	probeUnknown  probeOutcome = iota // old service or probe failed: run the export instead
	probeData                         // the tenant has rows
	probeEmpty                        // the tenant has no rows
	probeNotFound                     // no export endpoint at all
)

// get issues one S2S request to a service.
func (s *Service) get(ctx context.Context, url, accept string, tenantID uuid.UUID) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	// For the export, Accept marks the request as a stream so the service's timeout and
	// compression middleware stand aside (httpware.IsStreaming).
	req.Header.Set("Accept", accept)
	return s.http.Do(req)
}

// probe asks the service whether the tenant has any rows, without reading them. Services still on
// an httpware without probe answer with the export stream; that is detected from the content type
// and the body is dropped unread.
func (s *Service) probe(ctx context.Context, tenantID uuid.UUID, baseURL string) probeOutcome {
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	resp, err := s.get(pctx, baseURL+exportPath+"?probe=1", "application/json", tenantID)
	if err != nil {
		return probeUnknown
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return probeNotFound
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return probeUnknown
	}
	var pr tenantexport.ProbeResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pr); err != nil {
		return probeUnknown
	}
	if pr.HasData {
		return probeData
	}
	return probeEmpty
}

// fetch exports one service into a temp file. The stream lands there first, so an interrupted
// export never leaves a truncated entry in the archive, and its summary line is verified.
func (s *Service) fetch(ctx context.Context, tenantID uuid.UUID, name, baseURL string) part {
	ctx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()
	res := ServiceResult{Service: name}
	switch s.probe(ctx, tenantID, baseURL) {
	case probeEmpty:
		res.Status = ResultEmpty
		return part{res: res}
	case probeNotFound:
		res.Status = ResultUnavailable
		return part{res: res}
	}

	var lastErr string
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := s.get(ctx, baseURL+exportPath, tenantexport.ContentType, tenantID)
		if err != nil {
			lastErr = "service unreachable"
			s.log.Warn("tenant export request failed", zap.String("service", name), zap.Error(err))
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotFound:
			_ = resp.Body.Close()
			res.Status = ResultUnavailable
			return part{res: res}
		case resp.StatusCode >= 500 && attempt == 0:
			_ = resp.Body.Close()
			lastErr = fmt.Sprintf("service answered %d", resp.StatusCode)
			continue
		case resp.StatusCode != http.StatusOK:
			_ = resp.Body.Close()
			res.Status, res.Error = ResultFailed, fmt.Sprintf("service answered %d", resp.StatusCode)
			return part{res: res}
		}
		path, n, err := spool(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			s.log.Warn("tenant export interrupted", zap.String("service", name), zap.Error(err))
			res.Status, res.Error = ResultFailed, "export interrupted"
			return part{res: res}
		}
		rows, complete := verifySummary(path)
		switch {
		case !complete:
			_ = os.Remove(path)
			res.Status, res.Error = ResultFailed, "export incomplete"
			return part{res: res}
		case rows == 0:
			_ = os.Remove(path)
			res.Status = ResultEmpty
			return part{res: res}
		}
		res.Status, res.Bytes, res.Rows = ResultOK, n, rows
		return part{res: res, path: path}
	}
	res.Status, res.Error = ResultFailed, lastErr
	return part{res: res}
}

// spool copies a stream into a temp file.
func spool(body io.Reader) (string, int64, error) {
	f, err := os.CreateTemp("", "tenant-export-*.gz")
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(f, body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", 0, err
	}
	return f.Name(), n, nil
}

// verifySummary reads the gzipped JSON Lines file to its end and returns the row count of the
// summary line. complete is false when the gzip is damaged or the summary line is missing, which
// is how tenantexport signals a stream cut short after its first byte.
func verifySummary(path string) (rows int64, complete bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, false
	}
	dec := json.NewDecoder(gz)
	for {
		var line struct {
			Type string `json:"type"`
			Rows int64  `json:"rows"`
		}
		err := dec.Decode(&line)
		if errors.Is(err, io.EOF) {
			return rows, complete
		}
		if err != nil {
			return 0, false
		}
		if line.Type == "summary" {
			rows, complete = line.Rows, true
		}
	}
}
