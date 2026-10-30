package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/domains"
)

// DomainHandler serves self-service tenant domains: tenant admins manage their own from the SSO
// client area, platform owners any tenant's (same gate as tenant members, requireTenantAdmin).
type DomainHandler struct {
	svc       *domains.Service
	canManage func(r *http.Request, tenantID uuid.UUID) bool
	log       *zap.Logger
}

// NewDomainHandler builds the handler; canManage is the tenant-admin gate.
func NewDomainHandler(svc *domains.Service, canManage func(*http.Request, uuid.UUID) bool, log *zap.Logger) *DomainHandler {
	return &DomainHandler{svc: svc, canManage: canManage, log: log.Named("domains.http")}
}

func (h *DomainHandler) tenant(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return uuid.Nil, false
	}
	if !h.canManage(r, id) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return uuid.Nil, false
	}
	return id, true
}

func (h *DomainHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domains.ErrInvalidHostname), errors.Is(err, domains.ErrReservedHost), errors.Is(err, domains.ErrUnknownService):
		writeError(w, http.StatusBadRequest, "invalid_domain", err.Error(), nil)
	case errors.Is(err, domains.ErrHostTaken):
		writeError(w, http.StatusConflict, "domain_taken", err.Error(), nil)
	case errors.Is(err, domains.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error(), nil)
	case errors.Is(err, domains.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "domains_unavailable", err.Error(), nil)
	default:
		h.log.Error("tenant domains", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong", nil)
	}
}

// ListDomains handles GET /admin/tenants/{tenant_id}/domains.
func (h *DomainHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenant(w, r)
	if !ok {
		return
	}
	list, err := h.svc.List(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list, "enabled": h.svc.Enabled()})
}

// CreateDomain handles POST /admin/tenants/{tenant_id}/domains {hostname, service}.
func (h *DomainHandler) CreateDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var body struct {
		Hostname string `json:"hostname"`
		Service  string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid body", nil)
		return
	}
	createdBy := ""
	if c, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && c != nil {
		createdBy = c.Subject
	}
	d, err := h.svc.Create(r.Context(), id, body.Hostname, body.Service, createdBy)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

// RecheckDomain handles POST /admin/tenants/{tenant_id}/domains/{domain_id}/recheck.
func (h *DomainHandler) RecheckDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenant(w, r)
	if !ok {
		return
	}
	did, err := uuid.Parse(chi.URLParam(r, "domain_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid domain_id", nil)
		return
	}
	d, err := h.svc.Recheck(r.Context(), id, did)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// DeleteDomain handles DELETE /admin/tenants/{tenant_id}/domains/{domain_id}.
func (h *DomainHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := h.tenant(w, r)
	if !ok {
		return
	}
	did, err := uuid.Parse(chi.URLParam(r, "domain_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid domain_id", nil)
		return
	}
	if err := h.svc.Remove(r.Context(), id, did); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListServices handles GET /domains/services: what a domain can be connected to.
func (h *DomainHandler) ListServices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"data": domains.Services(), "enabled": h.svc.Enabled()})
}

// Resolve handles GET /domains/resolve?host= (public): which tenant and service a host serves.
// Frontends call it from their proxy to route a tenant's own domain to its storefront.
func (h *DomainHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Resolve(r.Context(), r.URL.Query().Get("host"))
	if err != nil {
		h.fail(w, err)
		return
	}
	if res == nil {
		writeError(w, http.StatusNotFound, "not_found", "no tenant domain for this host", nil)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, res)
}
