package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/app"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
)

// ClientChangedPrefix marks an apikey.changed broadcast that names an App by client_id rather
// than by key hash. Services that accept client_credentials tokens refuse any token for that
// client issued before the broadcast; services that only cache key hashes treat it as a hash
// that matches nothing, so the message is backward compatible.
const ClientChangedPrefix = "client:"

// consumerSecretPrefix identifies a consumer secret in logs and secret scanners.
const consumerSecretPrefix = "bng_cs_"

// generateConsumerSecret creates a consumer secret for the client_credentials grant:
// bng_cs_<base64url(32 random bytes)>. 256 bits of randomness make an unsalted SHA-256 hash
// safe to store, the same reasoning as generateAppToken.
func generateConsumerSecret() (secret, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate random bytes: %w", err)
	}
	secret = consumerSecretPrefix + base64.RawURLEncoding.EncodeToString(b)
	return secret, hashAPIKey(secret), nil
}

// announceAppChanged drops cached validations of the app's API key everywhere and tells
// client_credentials consumers to refuse its already-issued access tokens.
func announceAppChanged(a *ent.App) {
	if a == nil {
		return
	}
	announceKeyChanged(tenantIDOf(a), a.KeyHash, ClientChangedPrefix+a.ClientID)
}

// normalizeTenantScopes makes every "<service>:write" scope carry its "<service>:read"
// partner, since every external route requires read access and adds write for mutations. An
// app created with write alone could otherwise call nothing. Order is kept and duplicates
// are dropped.
func normalizeTenantScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return scopes
	}
	seen := make(map[string]bool, len(scopes)+2)
	out := make([]string, 0, len(scopes)+2)
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if svc, ok := strings.CutSuffix(s, ":write"); ok {
			add(svc + ":read")
		}
		add(s)
	}
	return out
}

// addedScopes returns the scopes in next that current does not hold.
func addedScopes(current, next []string) []string {
	have := make(map[string]bool, len(current))
	for _, s := range current {
		have[s] = true
	}
	var added []string
	for _, s := range next {
		if !have[s] {
			added = append(added, s)
		}
	}
	return added
}

// RotateSecret issues a new consumer secret for an app and returns it once. Tokens minted
// with the previous secret stop working: the new client_secret_rotated_at is announced to
// every consumer, which refuses tokens issued before it. Apps created before the
// client_credentials grant existed use this same call to get their first secret.
func (h *AppHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	appID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app id", nil)
		return
	}
	existing, err := h.ent.App.Get(r.Context(), appID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "app not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get app", nil)
		return
	}
	if !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "developer role required", nil)
			return
		}
	}
	if existing.Status == app.StatusRevoked {
		writeError(w, http.StatusConflict, "invalid_state", "a revoked app cannot get a new secret", nil)
		return
	}

	secret, hash, err := generateConsumerSecret()
	if err != nil {
		h.logger.Error("generate consumer secret", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "secret generation failed", nil)
		return
	}
	updated, err := h.ent.App.UpdateOneID(appID).
		SetClientSecretHash(hash).
		SetClientSecretRotatedAt(time.Now()).
		Save(r.Context())
	if err != nil {
		h.logger.Error("save consumer secret", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to rotate secret", nil)
		return
	}
	announceKeyChanged(tenantIDOf(existing), ClientChangedPrefix+existing.ClientID)
	h.logger.Info("app consumer secret rotated",
		zap.String("app_id", appID.String()),
		zap.String("rotated_by", claims.Subject),
	)
	writeJSON(w, http.StatusOK, CreateAppResponse{
		AppResponse:  appToResponse(updated),
		ClientSecret: secret,
	})
}
