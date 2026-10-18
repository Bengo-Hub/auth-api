package handlers

import (
	"errors"
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

func backupView(st *tenantbackup.State, downloadURL string) map[string]any {
	if st == nil {
		return map[string]any{"status": "none"}
	}
	v := map[string]any{
		"status":     st.Status,
		"started_at": st.StartedAt,
		"services":   st.Services,
	}
	if st.CompletedAt != nil {
		v["completed_at"] = st.CompletedAt
	}
	if st.Size > 0 {
		v["size"] = st.Size
	}
	if st.Error != "" {
		v["error"] = st.Error
	}
	if downloadURL != "" {
		v["download_url"] = downloadURL
	}
	return v
}

// GetTenantBackup returns the tenant's newest backup and, when one is ready, a 15-minute
// download link. GET /api/v1/admin/tenants/{tenant_id}/backup
func (h *AdminHandler) GetTenantBackup(w http.ResponseWriter, r *http.Request) {
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
	link := ""
	if st != nil && st.Key != "" {
		if link, err = h.tenantBackups.DownloadURL(st, slug); err != nil {
			h.logger.Warn("tenant backup link", zap.Error(err))
			link = ""
		}
	}
	writeJSON(w, http.StatusOK, backupView(st, link))
}

// StartTenantBackup starts a backup of every service's data for the tenant; it runs in the
// background (poll GET for progress). 409 while one is already running.
// POST /api/v1/admin/tenants/{tenant_id}/backup
func (h *AdminHandler) StartTenantBackup(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.backupTenant(w, r)
	if !ok {
		return
	}
	by := ""
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims != nil {
		by = claims.Subject
	}
	st, err := h.tenantBackups.Start(tenantID, by)
	if errors.Is(err, tenantbackup.ErrRunning) {
		writeJSON(w, http.StatusConflict, backupView(st, ""))
		return
	}
	if err != nil {
		h.logger.Error("start tenant backup", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to start the backup", nil)
		return
	}
	writeJSON(w, http.StatusAccepted, backupView(st, ""))
}
