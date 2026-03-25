package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// BackupHandler provides endpoints for platform admins to list and download PostgreSQL backups.
// Backups are served by an internal nginx service (backup-server) in the infra namespace.
type BackupHandler struct {
	backupServiceURL string
	enabled          bool
	httpClient       *http.Client
}

// NewBackupHandler creates a handler that proxies backup requests to the internal backup-server.
func NewBackupHandler(backupServiceURL string, enabled bool) *BackupHandler {
	return &BackupHandler{
		backupServiceURL: strings.TrimRight(backupServiceURL, "/"),
		enabled:          enabled,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // backups can be large
		},
	}
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

	resp, err := h.httpClient.Get(h.backupServiceURL + "/" + filename)
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
	io.Copy(w, resp.Body)
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
