package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
)

// UserHandler provides platform-admin user management APIs.
type UserHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

func NewUserHandler(entClient *ent.Client, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		ent:    entClient,
		logger: logger.Named("user_handler"),
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
// @Param search query string false "Search by email (case-insensitive)"
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
	search := strings.TrimSpace(q.Get("search"))
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := (page - 1) * limit

	query := h.ent.User.Query().WithMemberships()

	if statusFilter != "" {
		query = query.Where(user.StatusEQ(statusFilter))
	}
	if search != "" {
		query = query.Where(user.EmailContainsFold(search))
	}
	if tenantFilter != "" {
		tid, err := uuid.Parse(tenantFilter)
		if err == nil {
			query = query.Where(user.HasMembershipsWith(tenantmembership.TenantID(tid)))
		}
	}

	total, err := query.Clone().Count(r.Context())
	if err != nil {
		h.logger.Error("failed to count users", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to count users", nil)
		return
	}

	users, err := query.
		Order(ent.Desc(user.FieldCreatedAt)).
		Limit(limit).
		Offset(offset).
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

	writeJSON(w, http.StatusOK, map[string]any{
		"users": out,
		"pagination": map[string]any{
			"total":  total,
			"page":   page,
			"limit":  limit,
			"pages":  (total + limit - 1) / limit,
		},
	})
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
	if req.Phone != "" {
		profile["phone"] = req.Phone
	}
	if req.Bio != "" {
		profile["bio"] = req.Bio
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
	writeJSON(w, http.StatusOK, mapUser(updated))
}
