package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/modules/platformbackup"
	"github.com/go-chi/chi/v5"
)

// BackupHandler provides endpoints for platform admins to list and download PostgreSQL backups.
// Backups are served by an internal nginx service (backup-server) in the infra namespace.
// It also exposes the single-row platform auto-backup activation settings (opt-in, default OFF).
type BackupHandler struct {
	backupServiceURL string
	enabled          bool
	httpClient       *http.Client
	settings         *platformbackup.Service
}

// NewBackupHandler creates a handler that proxies backup requests to the internal backup-server
// and manages the platform auto-backup activation settings.
func NewBackupHandler(backupServiceURL string, enabled bool, settings *platformbackup.Service) *BackupHandler {
	return &BackupHandler{
		backupServiceURL: strings.TrimRight(backupServiceURL, "/"),
		enabled:          enabled,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // backups can be large
		},
		settings: settings,
	}
}

// GetSettings returns the platform auto-backup activation settings
// (GET /api/v1/admin/backups/settings). Admin-only via the /admin + RequireAuth group.
func (h *BackupHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if h.settings == nil {
		http.Error(w, `{"error":"backup settings unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	s, err := h.settings.Get(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to load settings: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

// UpdateSettings upserts the platform auto-backup activation settings
// (PUT /api/v1/admin/backups/settings). Admin-only via the /admin + RequireAuth group.
func (h *BackupHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h.settings == nil {
		http.Error(w, `{"error":"backup settings unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var in platformbackup.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	s, err := h.settings.Upsert(r.Context(), in)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to save settings: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

// ListBackups returns the backup manifest (GET /api/v1/platform/backups).
func (h *BackupHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		http.Error(w, `{"error":"backup feature is disabled"}`, http.StatusServiceUnavailable)
		return
	}

	resp, err := h.httpClient.Get(h.backupServiceURL + "/manifest.json")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to reach backup server: %s"}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// DownloadBackup streams a backup file (GET /api/v1/platform/backups/{filename}).
// Uses a dedicated HTTP client with no timeout to avoid the router's 60s middleware
// killing large file downloads. Streams data with flushing for real-time progress.
func (h *BackupHandler) DownloadBackup(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		http.Error(w, `{"error":"backup feature is disabled"}`, http.StatusServiceUnavailable)
		return
	}

	filename := chi.URLParam(r, "filename")
	if filename == "" {
		http.Error(w, `{"error":"filename is required"}`, http.StatusBadRequest)
		return
	}

	// Only allow .sql.gz files to prevent directory traversal
	if !strings.HasSuffix(filename, ".sql.gz") || strings.Contains(filename, "/") || strings.Contains(filename, "..") {
		http.Error(w, `{"error":"invalid filename"}`, http.StatusBadRequest)
		return
	}

	// Use a background-derived context for the upstream request.
	// The router's chimiddleware.Timeout(60s) cancels r.Context() after 60s,
	// which would kill the download. We use context.WithoutCancel so the
	// upstream fetch isn't affected by the middleware timeout, but still
	// cancel if the server shuts down.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.backupServiceURL+"/"+filename, nil)
	if err != nil {
		http.Error(w, `{"error":"failed to create request"}`, http.StatusInternalServerError)
		return
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to fetch backup: %s"}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		http.Error(w, `{"error":"backup file not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	if resp.ContentLength > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	}

	// Flush headers immediately so the browser can show progress
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Stream in 32KB chunks with flushing for real-time progress
	buf := make([]byte, 32*1024)
	flusher, canFlush := w.(http.Flusher)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return // client disconnected
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}
}

// BackupManifest is the JSON structure written by the CronJob.
type BackupManifest struct {
	Backups []BackupEntry `json:"backups"`
}

// BackupEntry represents a single backup file.
type BackupEntry struct {
	Filename  string `json:"filename"`
	Size      string `json:"size"`
	CreatedAt int64  `json:"created_at"`
}

// Ensure json import is used
var _ = json.Marshal
