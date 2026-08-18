package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"go.uber.org/zap"
)

type DeveloperHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

func NewDeveloperHandler(entClient *ent.Client, logger *zap.Logger) *DeveloperHandler {
	return &DeveloperHandler{
		ent:    entClient,
		logger: logger,
	}
}

func (h *DeveloperHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	// The auth-ui "Developer" page is platform-owner-only (see dashboard/layout.tsx
	// PLATFORM_OWNER_ROUTES); this API had no matching backend check, so any
	// authenticated user of any tenant could call it directly.
	if !claims.IsPlatformOwner {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	userID := parseUUID(claims.Subject)
	clients, err := h.ent.OAuthClient.Query().
		Where(oauthclient.CreatedBy(userID)).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list clients", nil)
		return
	}

	writeJSON(w, http.StatusOK, clients)
}

type createClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

func (h *DeveloperHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	// Minting a live OAuth client_id/client_secret against the platform's OIDC
	// endpoints is platform-admin only — previously any authenticated user,
	// any tenant, any role, could call this with no check at all.
	if !claims.IsPlatformOwner {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required", nil)
		return
	}

	var req createClientRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	clientID := randomString(32)
	clientSecret := randomString(64)
	userID := parseUUID(claims.Subject)

	client, err := h.ent.OAuthClient.Create().
		SetClientID(clientID).
		SetClientSecret(clientSecret).
		SetName(req.Name).
		SetRedirectUris(req.RedirectURIs).
		SetCreatedBy(userID).
		Save(r.Context())

	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create client", nil)
		return
	}

	writeJSON(w, http.StatusCreated, client)
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)[:n]
}
