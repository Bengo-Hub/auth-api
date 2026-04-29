package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type equityPortalClaimsKey struct{}

// EquityPortalHandler issues portal JWT links and serves equity portal data.
type EquityPortalHandler struct {
	ent      *ent.Client
	tokenSvc *token.Service
	logger   *zap.Logger
	issuer   string
}

func NewEquityPortalHandler(entClient *ent.Client, tokenSvc *token.Service, issuer string, logger *zap.Logger) *EquityPortalHandler {
	return &EquityPortalHandler{
		ent:      entClient,
		tokenSvc: tokenSvc,
		logger:   logger.Named("equity_portal"),
		issuer:   issuer,
	}
}

// GeneratePortalLink creates a signed JWT portal link for a treasury equity holder.
// POST /api/v1/admin/equity-holders/{treasury_holder_id}/portal-link
func (h *EquityPortalHandler) GeneratePortalLink(w http.ResponseWriter, r *http.Request) {
	if _, ok := authmiddleware.ClaimsFromContext(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}

	holderID := chi.URLParam(r, "treasury_holder_id")
	holderUUID, err := uuid.Parse(holderID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid treasury_holder_id", nil)
		return
	}

	portalToken, exp, err := h.tokenSvc.MintAccessToken(token.AccessTokenInput{
		UserID:    holderUUID,
		SessionID: uuid.New(),
		Scopes:    []string{"equity_portal"},
		Audience:  []string{h.issuer},
	})
	if err != nil {
		h.logger.Error("failed to mint portal token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate portal link", nil)
		return
	}

	portalURL := strings.TrimRight(h.issuer, "/") + "/equity-holder/?token=" + portalToken
	writeJSON(w, http.StatusOK, map[string]any{
		"url":        portalURL,
		"expires_at": exp.Format(time.RFC3339),
	})
}

// Me returns equity portal identity data authenticated via portal JWT.
// GET /api/v1/equity-portal/me
func (h *EquityPortalHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(equityPortalClaimsKey{}).(*token.Claims)
	if !ok || claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "portal token required", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"holder_id":  claims.Subject,
		"scope":      "equity_portal",
		"fetched_at": time.Now().Format(time.RFC3339),
	})
}

// EquityPortalAuth validates a Bearer token with scope=equity_portal.
func EquityPortalAuth(tokenSvc *token.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			if len(raw) < 8 || !strings.HasPrefix(raw, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "unauthorized", "portal token required", nil)
				return
			}
			claims, err := tokenSvc.Parse(raw[7:])
			if err != nil {
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid portal token", nil)
				return
			}
			for _, s := range claims.Scope {
				if s == "equity_portal" {
					ctx := context.WithValue(r.Context(), equityPortalClaimsKey{}, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			writeError(w, http.StatusForbidden, "forbidden", "token scope must be equity_portal", nil)
		})
	}
}
