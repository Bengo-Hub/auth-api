// Package tenantbackup builds a tenant's backup from the SSO client area: one export per service
// (each service streams its tenant rows through httpware/tenantexport), packed into one zip on the
// private object storage. Backups run on demand only (the platform pg_dumpall covers disaster
// recovery), only the newest is kept per tenant, and tenants download it through a presigned link.
// The state lives in tenants.metadata.backup, written with jsonb_set so other metadata writes are
// never overwritten.
package tenantbackup

import (
	"archive/zip"
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
)

// Status values of a tenant backup.
const (
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

const (
	exportPath = "/api/v1/s2s/tenant-export"
	// staleAfter lets a new backup start when a run stopped reporting (its pod restarted).
	staleAfter = 15 * time.Minute
	// jobTimeout bounds one backup run.
	jobTimeout = 45 * time.Minute
)

// ErrRunning is returned when a backup of the tenant is already in progress.
var ErrRunning = errors.New("a backup of this tenant is already running")

// ServiceResult is one service's part of a backup.
type ServiceResult struct {
	Service string `json:"service"`
	Status  string `json:"status"` // ok, unavailable (no export endpoint), failed
	Bytes   int64  `json:"bytes,omitempty"`
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
	Services    []ServiceResult `json:"services,omitempty"`
	Error       string          `json:"error,omitempty"`
}

// Service runs tenant backups.
type Service struct {
	db       *sql.DB
	store    *objectstore.Store
	services map[string]string // name -> base URL
	apiKey   string
	http     *http.Client
	log      *zap.Logger
	mu       sync.Mutex // serialises starts on this pod (the metadata check covers other pods)
}

// ParseServices reads "name=url,name=url".
func ParseServices(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		name, url, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(name) != "" && strings.TrimSpace(url) != "" {
			out[strings.TrimSpace(name)] = strings.TrimRight(strings.TrimSpace(url), "/")
		}
	}
	return out
}

// New builds the service. store must be the auth object store (backups are private).
func New(db *sql.DB, store *objectstore.Store, services map[string]string, apiKey string, log *zap.Logger) *Service {
	return &Service{db: db, store: store, services: services, apiKey: apiKey,
		http: &http.Client{Timeout: 0}, log: log.Named("tenantbackup")}
}

// Enabled reports whether backups can run here.
func (s *Service) Enabled() bool {
	return s != nil && s.store.Enabled() && len(s.services) > 0 && s.apiKey != ""
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

// Start begins a backup in the background and returns its initial state. Only one backup per
// tenant runs at a time; a run that stopped reporting for 15 minutes counts as abandoned.
func (s *Service) Start(tenantID uuid.UUID, requestedBy string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()
	prev, err := s.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if prev != nil && prev.Status == StatusRunning && time.Since(prev.HeartbeatAt) < staleAfter {
		return prev, ErrRunning
	}
	now := time.Now().UTC()
	st := &State{Status: StatusRunning, StartedAt: now, HeartbeatAt: now, RequestedBy: requestedBy}
	if prev != nil { // the previous archive stays downloadable until the new one completes
		st.Key, st.Size, st.CompletedAt = prev.Key, prev.Size, prev.CompletedAt
	}
	if err := s.save(ctx, tenantID, st); err != nil {
		return nil, err
	}
	go s.run(tenantID, st, prev)
	return st, nil
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

func (s *Service) run(tenantID uuid.UUID, st *State, prev *State) {
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()
	log := s.log.With(zap.String("tenant_id", tenantID.String()))
	fail := func(err error) {
		log.Error("tenant backup failed", zap.Error(err))
		st.Status, st.Error, st.HeartbeatAt = StatusFailed, err.Error(), time.Now().UTC()
		if prev != nil {
			st.Key, st.Size, st.CompletedAt = prev.Key, prev.Size, prev.CompletedAt
		}
		_ = s.save(context.Background(), tenantID, st)
	}

	tmp, err := os.CreateTemp("", "tenant-backup-*.zip")
	if err != nil {
		fail(err)
		return
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()

	zw := zip.NewWriter(tmp)
	names := make([]string, 0, len(s.services))
	for n := range s.services {
		names = append(names, n)
	}
	sort.Strings(names)
	st.Services = nil
	okCount := 0
	for _, name := range names {
		res := s.collect(ctx, zw, tenantID, name, s.services[name])
		st.Services = append(st.Services, res)
		if res.Status == "ok" {
			okCount++
		}
		st.HeartbeatAt = time.Now().UTC()
		_ = s.save(ctx, tenantID, st)
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"tenant_id": tenantID.String(), "generated_at": time.Now().UTC().Format(time.RFC3339),
		"services": st.Services,
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
		fail(errors.New("no service returned an export"))
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
	st.Status, st.Key, st.Size, st.CompletedAt, st.HeartbeatAt, st.Error = StatusCompleted, key, info.Size(), &done, done, ""
	if err := s.save(context.Background(), tenantID, st); err != nil {
		_ = s.store.Delete(context.Background(), key)
		fail(err)
		return
	}
	// Only the newest backup is kept.
	if prev != nil && prev.Key != "" && prev.Key != key && s.store.Owned(prev.Key) {
		if err := s.store.Delete(context.Background(), prev.Key); err != nil {
			log.Warn("previous tenant backup not deleted", zap.String("key", prev.Key), zap.Error(err))
		}
	}
	log.Info("tenant backup completed", zap.Int64("bytes", info.Size()), zap.Int("services", okCount))
}

// collect streams one service's export into its own zip entry. The stream is already gzipped,
// so the entry is stored as is. A service without the endpoint (404) is "unavailable".
func (s *Service) collect(ctx context.Context, zw *zip.Writer, tenantID uuid.UUID, name, baseURL string) ServiceResult {
	res := ServiceResult{Service: name}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+exportPath, nil)
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		return res
	}
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	// Marks the request as a stream, so the service's timeout and compression middleware stand
	// aside (httpware.IsStreaming).
	req.Header.Set("Accept", tenantexport.ContentType)
	resp, err := s.http.Do(req)
	if err != nil {
		res.Status, res.Error = "failed", "service unreachable"
		s.log.Warn("tenant export request failed", zap.String("service", name), zap.Error(err))
		return res
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		res.Status = "unavailable"
		return res
	case resp.StatusCode != http.StatusOK:
		res.Status, res.Error = "failed", fmt.Sprintf("service answered %d", resp.StatusCode)
		return res
	}
	// The stream lands in a temp file first, so an interrupted export never leaves a truncated
	// entry in the archive.
	part, err := os.CreateTemp("", "tenant-export-*.gz")
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		return res
	}
	defer func() { _ = part.Close(); _ = os.Remove(part.Name()) }()
	n, err := io.Copy(part, resp.Body)
	if err != nil {
		res.Status, res.Error = "failed", "export interrupted"
		s.log.Warn("tenant export interrupted", zap.String("service", name), zap.Error(err))
		return res
	}
	if _, err := part.Seek(0, io.SeekStart); err != nil {
		res.Status, res.Error = "failed", err.Error()
		return res
	}
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name + ".jsonl.gz", Method: zip.Store, Modified: time.Now()})
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
		return res
	}
	if _, err := io.Copy(w, part); err != nil {
		res.Status, res.Error = "failed", err.Error()
		return res
	}
	res.Status, res.Bytes = "ok", n
	return res
}
