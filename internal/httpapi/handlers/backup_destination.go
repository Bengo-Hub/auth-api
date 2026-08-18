package handlers

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/modules/platformbackup/destination"
)

// BackupDestinationHandler exposes platform-owner endpoints to view/set/test the
// remote destination that platform pg_dumpall backups are mirrored to. The local
// PVC copy is always kept as the durable primary + fallback; this only controls
// the optional remote mirror. Credentials are stored encrypted and never returned.
type BackupDestinationHandler struct {
	store    *destination.Store
	uploader *destination.Uploader
	logger   *zap.Logger
}

// NewBackupDestinationHandler builds the handler over the destination Store + Uploader.
func NewBackupDestinationHandler(store *destination.Store, uploader *destination.Uploader, logger *zap.Logger) *BackupDestinationHandler {
	return &BackupDestinationHandler{store: store, uploader: uploader, logger: logger.Named("backup.destination.handler")}
}

func (h *BackupDestinationHandler) respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type backupDestResponse struct {
	Configured bool                      `json:"configured"`
	Type       string                    `json:"type"`
	Enabled    bool                      `json:"enabled"`
	RemotePath string                    `json:"remote_path"`
	Params     []destination.MaskedParam `json:"params"`
}

func toBackupDestResponse(d destination.Destination, configured bool) backupDestResponse {
	params := d.MaskedParams()
	if params == nil {
		params = []destination.MaskedParam{}
	}
	return backupDestResponse{
		Configured: configured,
		Type:       string(d.Type),
		Enabled:    d.Enabled,
		RemotePath: d.RemotePath,
		Params:     params,
	}
}

type backupDestRequest struct {
	Type       string            `json:"type"`
	Enabled    bool              `json:"enabled"`
	RemotePath string            `json:"remote_path"`
	Params     map[string]string `json:"params"`
}

func (req backupDestRequest) toDestination() destination.Destination {
	return destination.Destination{
		Type:       destination.Type(req.Type),
		Enabled:    req.Enabled,
		RemotePath: req.RemotePath,
		Params:     req.Params,
	}
}

// mergeSecrets preserves an existing secret param value when the incoming request
// leaves it blank (so the UI can show "•••• set" without re-sending secrets).
func mergeSecrets(d *destination.Destination, existing destination.Destination, hadExisting bool) {
	if !hadExisting || d.Type != existing.Type {
		return
	}
	if d.Params == nil {
		d.Params = map[string]string{}
	}
	for _, k := range destination.SecretParamKeys(d.Type) {
		if d.Params[k] == "" && existing.Params[k] != "" {
			d.Params[k] = existing.Params[k]
		}
	}
}

// Get returns the masked platform backup destination (GET /api/v1/admin/backups/destination).
func (h *BackupDestinationHandler) Get(w http.ResponseWriter, r *http.Request) {
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); !ok || !requirePlatformAdmin(claims) {
		h.respond(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
		return
	}
	d, ok := h.store.Get(r.Context())
	if !ok {
		h.respond(w, http.StatusOK, backupDestResponse{Configured: false, Type: "pvc", Params: []destination.MaskedParam{}})
		return
	}
	h.respond(w, http.StatusOK, toBackupDestResponse(d, true))
}

// Update upserts the platform backup destination (PUT /api/v1/admin/backups/destination).
func (h *BackupDestinationHandler) Update(w http.ResponseWriter, r *http.Request) {
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); !ok || !requirePlatformAdmin(claims) {
		h.respond(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
		return
	}
	var req backupDestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respond(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	d := req.toDestination()
	existing, had := h.store.Get(r.Context())
	mergeSecrets(&d, existing, had)
	if err := d.Validate(); err != nil {
		h.respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.store.Store(r.Context(), d); err != nil {
		h.logger.Error("failed to store backup destination", zap.Error(err))
		h.respond(w, http.StatusInternalServerError, map[string]string{"error": "failed to save destination"})
		return
	}
	h.respond(w, http.StatusOK, toBackupDestResponse(d, true))
}

// Test verifies connectivity to a (possibly unsaved) destination
// (POST /api/v1/admin/backups/destination/test).
func (h *BackupDestinationHandler) Test(w http.ResponseWriter, r *http.Request) {
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); !ok || !requirePlatformAdmin(claims) {
		h.respond(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
		return
	}
	var req backupDestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respond(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	d := req.toDestination()
	existing, had := h.store.Get(r.Context())
	mergeSecrets(&d, existing, had)
	h.respond(w, http.StatusOK, h.uploader.TestConnection(r.Context(), d))
}
