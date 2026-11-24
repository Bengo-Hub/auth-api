package handlers

import (
	"errors"
	"net/http"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// signInMethodsPath is the accounts-portal page the link flow returns to (query string follows).
const signInMethodsPath = "/dashboard/profile?tab=security"

// --- Sign-in methods: social accounts linked to the signed-in person ---

// myLinkableUserID is the caller's id, or an error response. The shared demo account may not
// link or unlink: every visitor signs in to it.
func (h *AuthHandler) myLinkableUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return uuid.Nil, false
	}
	if demoSelfServiceBlocked(claims) {
		writeError(w, http.StatusForbidden, "demo_restricted", "sign-in methods cannot be changed on the shared demo account", nil)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id", nil)
		return uuid.Nil, false
	}
	return id, true
}

// ListMyIdentities lists the linked social sign-in methods.
// GET /api/v1/auth/me/identities
func (h *AuthHandler) ListMyIdentities(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	rows, hasPassword, err := h.service.SocialIdentities(r.Context(), userID)
	if err != nil {
		h.logger.Error("list user identities", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not load sign-in methods", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"id":             row.ID,
			"provider":       row.Provider,
			"email":          row.ProviderEmail,
			"email_verified": row.EmailVerified,
			"linked_at":      row.LinkedAt,
		}
		if name, _ := row.Profile["name"].(string); name != "" {
			item["name"] = name
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": out, "has_password": hasPassword})
}

// LinkMyIdentity starts linking a provider to the caller's account and returns the provider's
// authorization URL. POST /api/v1/auth/me/identities/{provider}/link
func (h *AuthHandler) LinkMyIdentity(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myLinkableUserID(w, r)
	if !ok {
		return
	}
	authURL, err := h.service.StartSocialLink(r.Context(), chi.URLParam(r, "provider"), userID, auth.OAuthStartInput{
		Origin:    r.Header.Get("Origin"),
		IPAddress: clientIP(r),
		UserAgent: userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorization_url": authURL})
}

// UnlinkMyIdentity removes a linked provider, never the last way to sign in.
// DELETE /api/v1/auth/me/identities/{id}
func (h *AuthHandler) UnlinkMyIdentity(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myLinkableUserID(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}
	err = h.service.UnlinkSocialIdentity(r.Context(), userID, id, clientIP(r), userAgent(r))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errors.Is(err, auth.ErrSocialIdentityNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error(), nil)
	case errors.Is(err, auth.ErrLastSignInMethod):
		writeError(w, http.StatusConflict, "last_sign_in_method", err.Error(), nil)
	default:
		h.logger.Error("unlink user identity", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not remove the sign-in method", nil)
	}
}
