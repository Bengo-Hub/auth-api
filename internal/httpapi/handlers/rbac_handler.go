package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Bengo-Hub/pagination"
	"github.com/bengobox/auth-api/internal/audit"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RBACHandler exposes Layer-1 role/permission/audit/password-policy management.
// It reuses the auth.Service for all data access so token issuance + membership
// resolution remain the single source of truth.
type RBACHandler struct {
	svc    *auth.Service
	logger *zap.Logger
}

// NewRBACHandler constructs an RBACHandler.
func NewRBACHandler(svc *auth.Service, logger *zap.Logger) *RBACHandler {
	return &RBACHandler{svc: svc, logger: logger}
}

// requireAdmin mirrors AdminHandler.requireAdmin: platform owners, superuser/
// admin roles, or admin-scoped S2S tokens may manage RBAC.
func (h *RBACHandler) requireAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}
	if claims.IsPlatformOwner {
		return true
	}
	for _, role := range claims.Roles {
		if role == "superuser" || role == "admin" {
			return true
		}
	}
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// actor extracts the acting user id/email from the request claims for audit logs.
func (h *RBACHandler) actor(r *http.Request) (*uuid.UUID, string, *uuid.UUID) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return nil, "", nil
	}
	var uid *uuid.UUID
	if id, err := uuid.Parse(claims.Subject); err == nil {
		uid = &id
	}
	var tid *uuid.UUID
	if claims.TenantID != "" {
		if id, err := uuid.Parse(claims.TenantID); err == nil {
			tid = &id
		}
	}
	return uid, claims.Email, tid
}

// writeAudit records a role/permission/security mutation.
func (h *RBACHandler) writeAudit(r *http.Request, action, resourceType, resourceID string, extra map[string]any) {
	uid, email, tid := h.actor(r)
	ctxData := map[string]any{}
	if email != "" {
		ctxData["actor_email"] = email
	}
	for k, v := range extra {
		ctxData[k] = v
	}
	h.svc.WriteAuditLog(r.Context(), audit.Entry{
		TenantID:   tid,
		UserID:     uid,
		Action:     action,
		Resource:   resourceType,
		ResourceID: resourceID,
		IPAddress:  clientIP(r),
		UserAgent:  userAgent(r),
		Context:    ctxData,
	})
}

// ─── Permissions ──────────────────────────────────────────────────────────────

// ListPermissions returns the permission catalogue grouped by service/module.
// GET /api/v1/admin/permissions
func (h *RBACHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	groups, err := h.svc.ListPermissionCatalogue(r.Context())
	if err != nil {
		h.logger.Error("list permission catalogue", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list permissions", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// ─── Roles ────────────────────────────────────────────────────────────────────

// ListRoles returns all roles with permission/member counts.
// GET /api/v1/admin/roles
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	roles, err := h.svc.ListRolesWithCounts(r.Context())
	if err != nil {
		h.logger.Error("list roles", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list roles", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

// GetRole returns one role plus its assigned permission codes.
// GET /api/v1/admin/roles/{role_code}
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	code := chi.URLParam(r, "role_code")
	summary, err := h.svc.GetRole(r.Context(), code)
	if err != nil {
		if errors.Is(err, auth.ErrRoleNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "role not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get role", nil)
		return
	}
	perms, err := h.svc.GetRolePermissions(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load role permissions", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"role":             summary,
		"permission_codes": perms,
	})
}

type createRoleRequest struct {
	RoleCode    string `json:"role_code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
}

// CreateRole creates a custom (non-system) role.
// POST /api/v1/admin/roles
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req createRoleRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.RoleCode) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "role_code is required", nil)
		return
	}
	role, err := h.svc.CreateRole(r.Context(), auth.CreateRoleInput{
		RoleCode:    strings.TrimSpace(req.RoleCode),
		Name:        req.Name,
		Description: req.Description,
		Scope:       req.Scope,
	})
	if err != nil {
		if errors.Is(err, auth.ErrRoleExists) {
			writeError(w, http.StatusConflict, "conflict", "role already exists", nil)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	h.writeAudit(r, "auth.role.created", "role", role.RoleCode, map[string]any{"name": role.Name})
	writeJSON(w, http.StatusCreated, role)
}

type updateRoleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Scope       *string `json:"scope"`
}

// UpdateRole edits a non-system role's metadata.
// PUT /api/v1/admin/roles/{role_code}
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	code := chi.URLParam(r, "role_code")
	var req updateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	role, err := h.svc.UpdateRole(r.Context(), code, auth.UpdateRoleInput{
		Name:        req.Name,
		Description: req.Description,
		Scope:       req.Scope,
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRoleNotFound):
			writeError(w, http.StatusNotFound, "not_found", "role not found", nil)
		case errors.Is(err, auth.ErrSystemRoleImmutable):
			writeError(w, http.StatusForbidden, "forbidden", "system role cannot be edited", nil)
		default:
			writeError(w, http.StatusInternalServerError, "server_error", "failed to update role", nil)
		}
		return
	}
	h.writeAudit(r, "auth.role.updated", "role", code, nil)
	writeJSON(w, http.StatusOK, role)
}

// DeleteRole deletes a non-system role and its RolePermission rows.
// DELETE /api/v1/admin/roles/{role_code}
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	code := chi.URLParam(r, "role_code")
	if err := h.svc.DeleteRole(r.Context(), code); err != nil {
		switch {
		case errors.Is(err, auth.ErrRoleNotFound):
			writeError(w, http.StatusNotFound, "not_found", "role not found", nil)
		case errors.Is(err, auth.ErrSystemRoleImmutable):
			writeError(w, http.StatusForbidden, "forbidden", "system role cannot be deleted", nil)
		default:
			writeError(w, http.StatusInternalServerError, "server_error", "failed to delete role", nil)
		}
		return
	}
	h.writeAudit(r, "auth.role.deleted", "role", code, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type setRolePermissionsRequest struct {
	PermissionCodes []string `json:"permission_codes"`
}

// SetRolePermissions reconciles the permission set for a role.
// PUT /api/v1/admin/roles/{role_code}/permissions
func (h *RBACHandler) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	code := chi.URLParam(r, "role_code")
	var req setRolePermissionsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	codes, err := h.svc.SetRolePermissions(r.Context(), code, req.PermissionCodes)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrWildcardRoleLocked):
			writeError(w, http.StatusForbidden, "forbidden", "permissions for this role are managed by the platform and cannot be edited", nil)
		case errors.Is(err, auth.ErrRoleNotFound):
			writeError(w, http.StatusNotFound, "not_found", "role not found", nil)
		default:
			h.logger.Error("set role permissions", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to set permissions", nil)
		}
		return
	}
	h.writeAudit(r, "auth.role.permissions_set", "role", code, map[string]any{"count": len(codes)})
	writeJSON(w, http.StatusOK, map[string]any{
		"role_code":        code,
		"permission_codes": codes,
	})
}

// ─── Audit logs ───────────────────────────────────────────────────────────────

// ListAuditLogs returns a paginated, filterable audit-log listing.
// GET /api/v1/admin/audit-logs?entity_type=&actor=&action=&from=&to=
func (h *RBACHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	p := pagination.Parse(r)
	q := auth.AuditQuery{
		ResourceType: r.URL.Query().Get("entity_type"),
		Action:       r.URL.Query().Get("action"),
		Limit:        p.Limit,
		Offset:       p.Offset,
	}
	if actor := r.URL.Query().Get("actor"); actor != "" {
		if id, err := uuid.Parse(actor); err == nil {
			q.ActorUserID = &id
		}
	}
	if tid := r.URL.Query().Get("tenant_id"); tid != "" {
		if id, err := uuid.Parse(tid); err == nil {
			q.TenantID = &id
		}
	}
	if from := r.URL.Query().Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			q.From = &t
		}
	}
	if to := r.URL.Query().Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			q.To = &t
		}
	}
	items, total, err := h.svc.QueryAuditLogs(r.Context(), q)
	if err != nil {
		h.logger.Error("query audit logs", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list audit logs", nil)
		return
	}
	writeJSON(w, http.StatusOK, pagination.NewResponse(items, total, p))
}

// ─── Password policy ──────────────────────────────────────────────────────────

// GetPasswordPolicy returns the platform-wide password policy.
// GET /api/v1/admin/password-policy
func (h *RBACHandler) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	policy, err := h.svc.GetPasswordPolicy(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load policy", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy})
}

// UpdatePasswordPolicy upserts the platform-wide password policy.
// PUT /api/v1/admin/password-policy
func (h *RBACHandler) UpdatePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req auth.PasswordPolicyData
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	policy, err := h.svc.SetPasswordPolicy(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update policy", nil)
		return
	}
	h.writeAudit(r, "auth.password_policy.updated", "password_policy", "platform", map[string]any{
		"min_length":     policy.MinLength,
		"require_symbol": policy.RequireSymbol,
		"expiry_days":    policy.ExpiryDays,
	})
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy})
}
