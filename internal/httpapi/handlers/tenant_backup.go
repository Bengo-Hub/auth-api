package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent/tenant"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/modules/tenantbackup"
)

// SetTenantBackups wires the tenant backup service (nil leaves the endpoints answering 503).
func (h *AdminHandler) SetTenantBackups(svc *tenantbackup.Service) { h.tenantBackups = svc }

func (h *AdminHandler) backupTenant(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return uuid.Nil, "", false
	}
	if !h.requireTenantAdmin(r, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return uuid.Nil, "", false
	}
	if !h.tenantBackups.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "backups_unavailable", "tenant backups are not configured", nil)
		return uuid.Nil, "", false
	}
	t, err := h.ent.Tenant.Query().Where(tenant.IDEQ(tenantID)).Select(tenant.FieldSlug).Only(r.Context())
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
		return uuid.Nil, "", false
	}
	return tenantID, t.Slug, true
}

// backupView is the status JSON. It never carries a download link: the link is issued by
// DownloadTenantBackup when the user asks for it, so polling does not mint presigned URLs.
func backupView(st *tenantbackup.State) map[string]any {
	if st == nil {
		return map[string]any{"status": "none"}
	}
	v := map[string]any{
		"status":     st.Status,
		"started_at": st.StartedAt,
		"services":   st.Services,
	}
	if len(st.Selected) > 0 {
		v["selected"] = st.Selected
	}
	if st.CompletedAt != nil {
		v["completed_at"] = st.CompletedAt
	}
	if st.Size > 0 {
		v["size"] = st.Size
	}
	if st.Key != "" {
		v["can_download"] = true
	}
	if st.Partial {
		v["partial"] = true
	}
	if st.Error != "" {
		v["error"] = st.Error
	}
	return v
}

func backupActor(r *http.Request) string {
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims != nil {
		return claims.Subject
	}
	return ""
}

// GetTenantBackup returns the tenant's newest backup and its per-service results.
// GET /api/v1/admin/tenants/{tenant_id}/backup
func (h *AdminHandler) GetTenantBackup(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.backupTenant(w, r)
	if !ok {
		return
	}
	st, err := h.tenantBackups.Get(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("read tenant backup state", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to read the backup", nil)
		return
	}
	writeJSON(w, http.StatusOK, backupView(st))
}

// DownloadTenantBackup issues a 15-minute download link for the newest backup and logs who asked.
// GET /api/v1/admin/tenants/{tenant_id}/backup/download
func (h *AdminHandler) DownloadTenantBackup(w http.ResponseWriter, r *http.Request) {
	tenantID, slug, ok := h.backupTenant(w, r)
	if !ok {
		return
	}
	st, err := h.tenantBackups.Get(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("read tenant backup state", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to read the backup", nil)
		return
	}
	if st == nil || st.Key == "" {
		writeError(w, http.StatusNotFound, "not_found", "no backup is ready to download", nil)
		return
	}
	link, err := h.tenantBackups.DownloadURL(st, slug)
	if err != nil {
		h.logger.Warn("tenant backup link", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to prepare the download", nil)
		return
	}
	h.logger.Info("tenant backup download link issued",
		zap.String("tenant_id", tenantID.String()), zap.String("requested_by", backupActor(r)))
	writeJSON(w, http.StatusOK, map[string]any{"download_url": link})
}

// BackupServices lists the services a backup can collect and which ones the tenant's plan covers,
// for the service picker. GET /api/v1/admin/tenants/{tenant_id}/backup/services
func (h *AdminHandler) BackupServices(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.backupTenant(w, r)
	if !ok {
		return
	}
	services, err := h.tenantBackups.Catalog(r.Context(), tenantID)
	if errors.Is(err, tenantbackup.ErrPlanUnverified) {
		writeError(w, http.StatusServiceUnavailable, "plan_unverified", "the plan could not be checked, try again shortly", nil)
		return
	}
	if err != nil {
		h.logger.Error("tenant backup catalog", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list services", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services})
}

// StartTenantBackup starts a backup in the background (poll GET for progress). The optional body
// {"services": ["pos", "inventory"]} picks services; without it every service in the tenant's plan
// is collected. 409 while one is already running.
// POST /api/v1/admin/tenants/{tenant_id}/backup
func (h *AdminHandler) StartTenantBackup(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.backupTenant(w, r)
	if !ok {
		return
	}
	var body struct {
		Services []string `json:"services"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read the request", nil)
		return
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body", nil)
			return
		}
	}
	st, err := h.tenantBackups.Start(r.Context(), tenantID, backupActor(r), body.Services)
	switch {
	case errors.Is(err, tenantbackup.ErrRunning):
		writeJSON(w, http.StatusConflict, backupView(st))
		return
	case errors.Is(err, tenantbackup.ErrUnknownService), errors.Is(err, tenantbackup.ErrNotInPlan),
		errors.Is(err, tenantbackup.ErrNothingToBackup):
		writeError(w, http.StatusBadRequest, "invalid_services", err.Error(), nil)
		return
	case errors.Is(err, tenantbackup.ErrPlanUnverified):
		writeError(w, http.StatusServiceUnavailable, "plan_unverified", "the plan could not be checked, try again shortly", nil)
		return
	case err != nil:
		h.logger.Error("start tenant backup", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to start the backup", nil)
		return
	}
	h.logger.Info("tenant backup started",
		zap.String("tenant_id", tenantID.String()), zap.String("requested_by", backupActor(r)), zap.Strings("services", body.Services))
	writeJSON(w, http.StatusAccepted, backupView(st))
}
