package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/Bengo-Hub/pagination"
	"github.com/bengobox/auth-api/internal/ent/authorizationcode"
	"github.com/bengobox/auth-api/internal/ent/consentsession"
	"github.com/bengobox/auth-api/internal/ent/mfabackupcode"
	"github.com/bengobox/auth-api/internal/ent/mfasettings"
	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
	"github.com/bengobox/auth-api/internal/ent/passwordresettoken"
	"github.com/bengobox/auth-api/internal/ent/predicate"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useremail"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
	"github.com/bengobox/auth-api/internal/ent/userphone"
	"github.com/bengobox/auth-api/internal/ent/webauthncredential"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
)

// UserHandler provides platform-admin user management APIs.
type UserHandler struct {
	ent            *ent.Client
	logger         *zap.Logger
	hasher         *password.Hasher
	auth           AuthService // for admin-initiated password-reset emails
	redis          *redis.Client
	redisNamespace string
	authUIURL      string
}

func NewUserHandler(entClient *ent.Client, hasher *password.Hasher, authSvc AuthService, redisClient *redis.Client, redisNamespace, authUIURL string, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		ent:            entClient,
		logger:         logger.Named("user_handler"),
		hasher:         hasher,
		auth:           authSvc,
		redis:          redisClient,
		redisNamespace: redisNamespace,
		authUIURL:      authUIURL,
	}
}

func (h *UserHandler) requirePlatformAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	return ok && claims != nil && claims.IsPlatformOwner
}

// userResponse is the public representation of a user (no password hash).
type userResponse struct {
	ID             uuid.UUID              `json:"id"`
	Email          string                 `json:"email"`
	Status         string                 `json:"status"`
	PrimaryTenantID string               `json:"primary_tenant_id,omitempty"`
	Profile        map[string]any         `json:"profile,omitempty"`
	LastLoginAt    *time.Time             `json:"last_login_at,omitempty"`
	TermsAccepted  bool                   `json:"terms_accepted"`
	Memberships    []membershipSummary    `json:"memberships,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type membershipSummary struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Roles    []string  `json:"roles"`
	Status   string    `json:"status"`
}

func mapUser(u *ent.User) *userResponse {
	resp := &userResponse{
		ID:              u.ID,
		Email:           u.Email,
		Status:          u.Status,
		PrimaryTenantID: u.PrimaryTenantID,
		Profile:         u.Profile,
		TermsAccepted:   u.TermsAccepted,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
	if !u.LastLoginAt.IsZero() {
		resp.LastLoginAt = &u.LastLoginAt
	}
	for _, m := range u.Edges.Memberships {
		resp.Memberships = append(resp.Memberships, membershipSummary{
			TenantID: m.TenantID,
			Roles:    m.Roles,
			Status:   m.Status,
		})
	}
	return resp
}

// AdminListUsers godoc
// @Summary List all users (platform admin only)
// @Tags admin/users
// @Produce json
// @Param status query string false "Filter by status (active, suspended, deactivated)"
// @Param tenant_id query string false "Filter by tenant membership"
// @Param role query string false "Filter by role held in any (or the given) tenant membership"
// @Param search query string false "Search by email or name (case-insensitive)"
// @Param page query int false "Page number (1-based)"
// @Param limit query int false "Page size (default 50)"
// @Success 200 {object} map[string]any
func (h *UserHandler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	q := r.URL.Query()
	statusFilter := q.Get("status")
	tenantFilter := q.Get("tenant_id")
	roleFilter := strings.TrimSpace(q.Get("role"))
	search := strings.TrimSpace(q.Get("search"))
	p := pagination.Parse(r)

	query := h.ent.User.Query().WithMemberships()

	if statusFilter != "" {
		query = query.Where(user.StatusEQ(statusFilter))
	}
	if search != "" {
		// Match email OR the display name stored in profile->>'name' (case-insensitive).
		like := "%" + search + "%"
		query = query.Where(func(s *entsql.Selector) {
			s.Where(entsql.Or(
				entsql.ExprP(s.C(user.FieldEmail)+" ILIKE ?", like),
				entsql.ExprP("("+s.C(user.FieldProfile)+"->>'name') ILIKE ?", like),
			))
		})
	}

	// tenant_id and role both constrain tenant memberships; when both are present
	// they must be satisfied by the SAME membership (a user holding that role in
	// that specific tenant), so they are ANDed inside one HasMembershipsWith.
	var memberPreds []predicate.TenantMembership
	if tenantFilter != "" {
		if tid, err := uuid.Parse(tenantFilter); err == nil {
			memberPreds = append(memberPreds, tenantmembership.TenantID(tid))
		}
	}
	if roleFilter != "" {
		memberPreds = append(memberPreds, func(s *entsql.Selector) {
			s.Where(sqljson.ValueContains(tenantmembership.FieldRoles, roleFilter))
		})
	}
	if len(memberPreds) > 0 {
		query = query.Where(user.HasMembershipsWith(memberPreds...))
	}

	total, err := query.Clone().Count(r.Context())
	if err != nil {
		h.logger.Error("failed to count users", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to count users", nil)
		return
	}

	users, err := query.
		Order(ent.Desc(user.FieldCreatedAt)).
		Limit(p.Limit).
		Offset(p.Offset).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list users", nil)
		return
	}

	out := make([]*userResponse, len(users))
	for i, u := range users {
		out[i] = mapUser(u)
	}

	writeJSON(w, http.StatusOK, pagination.NewResponse(out, total, p))
}

// AdminGetUser godoc
// @Summary Get a single user by ID (platform admin only)
func (h *UserHandler) AdminGetUser(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	u, err := h.ent.User.Query().Where(user.ID(userID)).WithMemberships().Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get user", nil)
		return
	}

	writeJSON(w, http.StatusOK, mapUser(u))
}

type updateUserRequest struct {
	Email   string         `json:"email,omitempty"`
	Profile map[string]any `json:"profile,omitempty"`
}

// AdminUpdateUser godoc
// @Summary Edit user email or profile (platform admin only)
func (h *UserHandler) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body", nil)
		return
	}

	upd := h.ent.User.UpdateOneID(userID)
	if req.Email != "" {
		upd = upd.SetEmail(req.Email)
	}
	if req.Profile != nil {
		upd = upd.SetProfile(req.Profile)
	}

	u, err := upd.Save(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		if ent.IsConstraintError(err) {
			writeError(w, http.StatusConflict, "conflict", "email already in use", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update user", nil)
		return
	}

	writeJSON(w, http.StatusOK, mapUser(u))
}

func (h *UserHandler) setUserStatus(w http.ResponseWriter, r *http.Request, status string) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	u, err := h.ent.User.UpdateOneID(userID).SetStatus(status).Save(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update user status", nil)
		return
	}

	h.logger.Info("user status changed",
		zap.String("user_id", userID.String()),
		zap.String("status", status))

	// Publish auth.user.deactivated so downstream projections (notifications, pos,
	// inventory, erp, ordering, logistics) can react — e.g. stop notifying / disable the
	// local user. The consumers already subscribe to this subject; it simply was never
	// emitted. Only non-active statuses deactivate; re-activation is a separate concern.
	if status == "deactivated" || status == "suspended" || status == "inactive" {
		tenantID := uuid.Nil
		if u.PrimaryTenantID != "" {
			tenantID, _ = uuid.Parse(u.PrimaryTenantID)
		}
		writeOutboxEvent(r.Context(), h.ent, h.logger, tenantID, "auth.user", u.ID, "deactivated", map[string]any{
			"user_id":   u.ID.String(),
			"tenant_id": u.PrimaryTenantID,
			"email":     u.Email,
			"status":    status,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": u.ID, "status": u.Status})
}

// AdminSuspendUser temporarily blocks a user from signing in.
func (h *UserHandler) AdminSuspendUser(w http.ResponseWriter, r *http.Request) {
	h.setUserStatus(w, r, "suspended")
}

// AdminDeactivateUser marks a user as deactivated (long-term inactive).
func (h *UserHandler) AdminDeactivateUser(w http.ResponseWriter, r *http.Request) {
	h.setUserStatus(w, r, "deactivated")
}

// AdminActivateUser restores an account to active status.
func (h *UserHandler) AdminActivateUser(w http.ResponseWriter, r *http.Request) {
	h.setUserStatus(w, r, "active")
}

// AdminDeleteUser soft-deletes a user by setting status to "deleted".
// The record is retained for audit purposes.
func (h *UserHandler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	_, err = h.ent.User.UpdateOneID(userID).SetStatus("deleted").Save(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete user", nil)
		return
	}

	h.logger.Info("user soft-deleted", zap.String("user_id", userID.String()))
	w.WriteHeader(http.StatusNoContent)
}

// AdminPurgeUser permanently and irreversibly deletes a user and ALL of their
// identity data (sessions, refresh/reset tokens, MFA secrets, WebAuthn
// credentials, linked emails/phones, OAuth consent grants, tenant
// memberships) — a TRUE hard delete, unlike AdminDeleteUser above which only
// soft-deletes (status="deleted", record retained for audit purposes).
// LoginAttempt and AuditLog rows are intentionally left in place with a now-
// dangling user_id: those are security/compliance records, not identity
// data, and existed with no ent edge back to User for exactly this reason.
// Emits `auth.user.deleted` (outbox) after a successful commit so downstream
// services can remove their own local shadow-user data; enforcement of what
// gets deleted downstream is each service's own responsibility.
// POST /api/v1/admin/users/{user_id}/purge
func (h *UserHandler) AdminPurgeUser(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims != nil {
		if selfID, parseErr := uuid.Parse(claims.Subject); parseErr == nil && selfID == userID {
			writeError(w, http.StatusBadRequest, "cannot_self_delete", "you cannot hard-delete your own account", nil)
			return
		}
	}

	ctx := r.Context()
	u, err := h.ent.User.Get(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load user", nil)
		return
	}

	// Capture tenant memberships before they're deleted — downstream consumers scope
	// their local shadow data by tenant, so the event needs every tenant this user
	// belonged to, not just their primary one.
	memberships, err := h.ent.TenantMembership.Query().Where(tenantmembership.UserID(userID)).All(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load memberships", nil)
		return
	}
	tenantIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		tenantIDs = append(tenantIDs, m.TenantID.String())
	}

	tx, err := h.ent.Tx(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to start transaction", nil)
		return
	}

	cascades := []func() error{
		func() error { _, e := tx.Session.Delete().Where(session.UserID(userID)).Exec(ctx); return e },
		func() error {
			_, e := tx.PasswordResetToken.Delete().Where(passwordresettoken.UserID(userID)).Exec(ctx)
			return e
		},
		func() error { _, e := tx.UserIdentity.Delete().Where(useridentity.UserID(userID)).Exec(ctx); return e },
		func() error {
			_, e := tx.AuthorizationCode.Delete().Where(authorizationcode.UserID(userID)).Exec(ctx)
			return e
		},
		func() error { _, e := tx.MFATOTPSecret.Delete().Where(mfatotpsecret.UserID(userID)).Exec(ctx); return e },
		func() error { _, e := tx.MFABackupCode.Delete().Where(mfabackupcode.UserID(userID)).Exec(ctx); return e },
		func() error {
			_, e := tx.WebAuthnCredential.Delete().Where(webauthncredential.UserID(userID)).Exec(ctx)
			return e
		},
		func() error { _, e := tx.UserEmail.Delete().Where(useremail.UserID(userID)).Exec(ctx); return e },
		func() error { _, e := tx.UserPhone.Delete().Where(userphone.UserID(userID)).Exec(ctx); return e },
		func() error { _, e := tx.MFASettings.Delete().Where(mfasettings.UserID(userID)).Exec(ctx); return e },
		func() error { _, e := tx.ConsentSession.Delete().Where(consentsession.UserID(userID)).Exec(ctx); return e },
		func() error {
			_, e := tx.TenantMembership.Delete().Where(tenantmembership.UserID(userID)).Exec(ctx)
			return e
		},
	}
	for _, cascade := range cascades {
		if cErr := cascade(); cErr != nil {
			_ = tx.Rollback()
			h.logger.Error("purge user: cascade delete failed", zap.String("user_id", userID.String()), zap.Error(cErr))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to purge related data", nil)
			return
		}
	}

	if err := tx.User.DeleteOneID(userID).Exec(ctx); err != nil {
		_ = tx.Rollback()
		h.logger.Error("purge user: delete user row failed", zap.String("user_id", userID.String()), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete user", nil)
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("purge user: commit failed", zap.String("user_id", userID.String()), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to commit purge", nil)
		return
	}

	invalidateMeCacheKeys(ctx, h.redis, h.redisNamespace, userID)

	var primaryTenantID uuid.UUID
	if u.PrimaryTenantID != "" {
		primaryTenantID, _ = uuid.Parse(u.PrimaryTenantID)
	}
	writeOutboxEvent(ctx, h.ent, h.logger, primaryTenantID, "auth.user", userID, "deleted", map[string]any{
		"user_id":           userID.String(),
		"email":             u.Email,
		"primary_tenant_id": u.PrimaryTenantID,
		"tenant_ids":        tenantIDs,
	})

	h.logger.Info("user hard-deleted (purged)", zap.String("user_id", userID.String()), zap.String("email", u.Email))
	w.WriteHeader(http.StatusNoContent)
}

type createUserRequest struct {
	Email           string `json:"email"`
	Name            string `json:"name,omitempty"`
	Phone           string `json:"phone,omitempty"`
	Password        string `json:"password,omitempty"` // optional; generated if empty
	PrimaryTenantID string `json:"primary_tenant_id,omitempty"`
}

// AdminCreateUser creates a new user account directly (platform admin only).
// POST /api/v1/admin/users
// When no password is supplied a temporary one is generated and returned ONCE;
// the user is flagged to change it on first interactive login. A welcome event
// is published so notifications-service can email the SSO login link.
func (h *UserHandler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body", nil)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email is required", nil)
		return
	}

	tempPassword := strings.TrimSpace(req.Password)
	generated := false
	if tempPassword == "" {
		tempPassword = generateTempPassword()
		generated = true
	}
	hash, err := h.hasher.Hash(tempPassword)
	if err != nil {
		h.logger.Error("hash password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not create user", nil)
		return
	}

	profile := map[string]any{"must_change_password": true}
	if strings.TrimSpace(req.Name) != "" {
		profile["name"] = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.Phone) != "" {
		profile["phone"] = strings.TrimSpace(req.Phone)
	}

	create := h.ent.User.Create().
		SetEmail(email).
		SetPasswordHash(hash).
		SetStatus("active").
		SetProfile(profile)
	if strings.TrimSpace(req.PrimaryTenantID) != "" {
		create = create.SetPrimaryTenantID(strings.TrimSpace(req.PrimaryTenantID))
	}

	u, err := create.Save(r.Context())
	if err != nil {
		if ent.IsConstraintError(err) {
			writeError(w, http.StatusConflict, "conflict", "email already in use", nil)
			return
		}
		h.logger.Error("create user", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not create user", nil)
		return
	}

	// Welcome event so notifications-service can email the SSO login link.
	tenantID := uuid.Nil
	if u.PrimaryTenantID != "" {
		if tid, pErr := uuid.Parse(u.PrimaryTenantID); pErr == nil {
			tenantID = tid
		}
	}
	writeOutboxEvent(r.Context(), h.ent, h.logger, tenantID, "auth.user", u.ID, "created", map[string]any{
		"user_id":              u.ID.String(),
		"email":                u.Email,
		"full_name":            profileStr(u.Profile, "name"),
		"method":               "admin_provisioned",
		"welcome":              true,
		"must_change_password": true,
		"login_url":            h.authUIURL,
	})

	resp := mapUser(u)
	out := map[string]any{
		"id":             resp.ID,
		"email":          resp.Email,
		"status":         resp.Status,
		"primary_tenant_id": resp.PrimaryTenantID,
		"profile":        resp.Profile,
		"created_at":     resp.CreatedAt,
		"updated_at":     resp.UpdatedAt,
	}
	if generated {
		out["temp_password"] = tempPassword
	}
	writeJSON(w, http.StatusCreated, out)
}

type adminResetPasswordRequest struct {
	NewPassword string `json:"new_password,omitempty"` // optional; generated if empty
}

// AdminResetPassword sets a user's password directly without the current
// password (platform admin only). POST /api/v1/admin/users/{user_id}/reset-password
// Generates a temporary password when none is supplied and returns it ONCE.
func (h *UserHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	var req adminResetPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body", nil)
		return
	}

	newPassword := strings.TrimSpace(req.NewPassword)
	generated := false
	if newPassword == "" {
		newPassword = generateTempPassword()
		generated = true
	}
	hash, err := h.hasher.Hash(newPassword)
	if err != nil {
		h.logger.Error("hash password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not reset password", nil)
		return
	}

	u, err := h.ent.User.Get(r.Context(), userID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load user", nil)
		return
	}

	// Force a change on next interactive login.
	profile := make(map[string]any)
	for k, v := range u.Profile {
		profile[k] = v
	}
	profile["must_change_password"] = true

	if err := h.ent.User.UpdateOneID(userID).SetPasswordHash(hash).SetProfile(profile).Exec(r.Context()); err != nil {
		h.logger.Error("reset password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not reset password", nil)
		return
	}
	h.invalidateMeCache(r.Context(), userID)
	h.logger.Info("admin reset user password", zap.String("user_id", userID.String()))

	out := map[string]any{"id": userID, "status": "password_reset"}
	if generated {
		out["temp_password"] = newPassword
	}
	writeJSON(w, http.StatusOK, out)
}

// AdminSendPasswordResetEmail triggers the standard password-reset email for a
// user (platform admin only). POST /api/v1/admin/users/{user_id}/send-password-reset
func (h *UserHandler) AdminSendPasswordResetEmail(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	u, err := h.ent.User.Get(r.Context(), userID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load user", nil)
		return
	}

	// Resolve the user's tenant slug (RequestPasswordReset is tenant-scoped and
	// verifies membership). Prefer the primary tenant, else the first membership.
	slug := ""
	if u.PrimaryTenantID != "" {
		if tid, pErr := uuid.Parse(u.PrimaryTenantID); pErr == nil {
			if t, tErr := h.ent.Tenant.Get(r.Context(), tid); tErr == nil {
				slug = t.Slug
			}
		}
	}
	if slug == "" {
		if m, mErr := h.ent.TenantMembership.Query().Where(tenantmembership.UserID(userID)).WithTenant().First(r.Context()); mErr == nil && m.Edges.Tenant != nil {
			slug = m.Edges.Tenant.Slug
		}
	}
	if slug == "" {
		writeError(w, http.StatusBadRequest, "no_tenant", "user has no tenant to scope the reset email", nil)
		return
	}

	resetInput := auth.PasswordResetRequestInput{
		Email:      u.Email,
		TenantSlug: slug,
		IPAddress:  clientIP(r),
		UserAgent:  userAgent(r),
	}
	if _, err := h.auth.RequestPasswordReset(r.Context(), resetInput); err != nil {
		h.logger.Warn("admin send password reset email failed", zap.Error(err), zap.String("user_id", userID.String()))
		// Do not leak whether the account/membership exists.
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset_email_sent"})
}

type adminMfaEnforcementRequest struct {
	Enforced bool `json:"enforced"`
}

// AdminSetMfaEnforcement records whether 2FA is enforced for a user (platform
// admin only). POST /api/v1/admin/users/{user_id}/mfa-enforcement
// Sets/clears MFASettings.enforced_at. Step-up enforcement at login is a follow-up.
func (h *UserHandler) AdminSetMfaEnforcement(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}
	var req adminMfaEnforcementRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body", nil)
		return
	}

	existing, _ := h.ent.MFASettings.Query().Where(mfasettings.UserID(userID)).Only(r.Context())
	if existing == nil {
		create := h.ent.MFASettings.Create().SetUserID(userID)
		if req.Enforced {
			create = create.SetEnforcedAt(time.Now())
		}
		if _, err := create.Save(r.Context()); err != nil {
			h.logger.Error("create mfa settings", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "could not update 2FA enforcement", nil)
			return
		}
	} else {
		upd := existing.Update()
		if req.Enforced {
			upd = upd.SetEnforcedAt(time.Now())
		} else {
			upd = upd.ClearEnforcedAt()
		}
		if _, err := upd.Save(r.Context()); err != nil {
			h.logger.Error("update mfa settings", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "could not update 2FA enforcement", nil)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": userID, "mfa_enforced": req.Enforced})
}

// invalidateMeCache deletes any cached /me responses for a user so a subsequent
// load reflects profile/password/status changes immediately.
func (h *UserHandler) invalidateMeCache(ctx context.Context, userID uuid.UUID) {
	invalidateMeCacheKeys(ctx, h.redis, h.redisNamespace, userID)
}

// UpdateMyProfile lets any authenticated user update their own profile fields
// stored in the profile JSON column. Merges the provided fields into the
// existing profile so callers only need to send what changed.
// PATCH /api/v1/auth/me
func (h *UserHandler) UpdateMyProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id", nil)
		return
	}

	var req struct {
		Name              string         `json:"name,omitempty"`
		ProfilePictureURL string         `json:"profile_picture_url,omitempty"`
		Phone             string         `json:"phone,omitempty"`
		Bio               string         `json:"bio,omitempty"`
		Country           string         `json:"country,omitempty"`
		Gender            string         `json:"gender,omitempty"`
		Timezone          string         `json:"timezone,omitempty"`
		Locale            string         `json:"locale,omitempty"`
		Preferences       map[string]any `json:"preferences,omitempty"`
		// Notification settings (email/sms/push/whatsapp toggles)
		NotificationSettings map[string]any `json:"notification_settings,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid body", nil)
		return
	}

	// Validate BEFORE touching anything — a bad phone/country must not partially
	// apply the rest of the update.
	var normalizedPhone string
	if req.Phone != "" {
		normalizedPhone, err = validateAndNormalizePhone(req.Phone)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_phone", "Enter a valid phone number, including country code.", nil)
			return
		}
	}
	if req.Country != "" && !isValidCountryCode(req.Country) {
		writeError(w, http.StatusBadRequest, "invalid_country", "Unrecognized country code.", nil)
		return
	}

	u, err := h.ent.User.Get(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load user", nil)
		return
	}

	// Merge into existing profile JSON
	profile := make(map[string]any)
	for k, v := range u.Profile {
		profile[k] = v
	}
	if req.Name != "" {
		profile["name"] = req.Name
	}
	if req.ProfilePictureURL != "" {
		profile["profile_picture_url"] = req.ProfilePictureURL
	}
	if normalizedPhone != "" {
		profile["phone"] = normalizedPhone
	}
	if req.Bio != "" {
		profile["bio"] = req.Bio
	}
	if req.Country != "" {
		profile["country"] = strings.ToUpper(req.Country)
	}
	if req.Gender != "" {
		profile["gender"] = req.Gender
	}
	if req.Timezone != "" {
		profile["timezone"] = req.Timezone
	}
	if req.Locale != "" {
		profile["locale"] = req.Locale
	}
	if len(req.Preferences) > 0 {
		existing, _ := profile["preferences"].(map[string]any)
		if existing == nil {
			existing = make(map[string]any)
		}
		for k, v := range req.Preferences {
			existing[k] = v
		}
		profile["preferences"] = existing
	}
	if len(req.NotificationSettings) > 0 {
		existing, _ := profile["notification_settings"].(map[string]any)
		if existing == nil {
			existing = make(map[string]any)
		}
		for k, v := range req.NotificationSettings {
			existing[k] = v
		}
		profile["notification_settings"] = existing
	}

	updated, err := h.ent.User.UpdateOneID(userID).SetProfile(profile).Save(r.Context())
	if err != nil {
		h.logger.Error("update my profile", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update profile", nil)
		return
	}
	// Bust the cached /me response so a reload reflects the change immediately.
	h.invalidateMeCache(r.Context(), userID)
	writeJSON(w, http.StatusOK, mapUser(updated))
}
