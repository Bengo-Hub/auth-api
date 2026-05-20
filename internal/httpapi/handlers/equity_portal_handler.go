package handlers

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/portalshortlink"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type equityPortalClaimsKey struct{}

const shortCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const shortCodeLen = 8

// generateShortCode returns an 8-char uppercase alphanumeric code using crypto/rand.
func generateShortCode() (string, error) {
	b := make([]byte, shortCodeLen)
	alphabetSize := big.NewInt(int64(len(shortCodeAlphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, alphabetSize)
		if err != nil {
			return "", err
		}
		b[i] = shortCodeAlphabet[n.Int64()]
	}
	return string(b), nil
}

// EquityPortalHandler issues portal JWT links and serves equity portal data.
type EquityPortalHandler struct {
	ent       *ent.Client
	tokenSvc  *token.Service
	logger    *zap.Logger
	issuer    string
	uiBaseURL string
}

// NewEquityPortalHandler creates the handler.
// issuer      — JWT issuer (e.g. https://sso.codevertexitsolutions.com)
// uiBaseURL   — base URL of the auth-ui frontend (e.g. https://accounts.codevertexitsolutions.com)
func NewEquityPortalHandler(entClient *ent.Client, tokenSvc *token.Service, issuer, uiBaseURL string, logger *zap.Logger) *EquityPortalHandler {
	return &EquityPortalHandler{
		ent:       entClient,
		tokenSvc:  tokenSvc,
		logger:    logger.Named("equity_portal"),
		issuer:    issuer,
		uiBaseURL: uiBaseURL,
	}
}

// GeneratePortalLink creates a signed JWT portal link for a treasury equity holder
// and also persists a short link for easy sharing.
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

	// Full portal URL points to auth-ui frontend, not the API issuer.
	portalURL := strings.TrimRight(h.uiBaseURL, "/") + "/equity-holder/?token=" + portalToken

	// Create short link (retry up to 3 times on code collision).
	var shortCode string
	for attempt := 0; attempt < 3; attempt++ {
		code, codeErr := generateShortCode()
		if codeErr != nil {
			h.logger.Error("failed to generate short code", zap.Error(codeErr))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to generate short link", nil)
			return
		}
		_, dbErr := h.ent.PortalShortLink.Create().
			SetCode(code).
			SetHolderID(holderUUID).
			SetJwtToken(portalToken).
			SetExpiresAt(exp).
			Save(r.Context())
		if dbErr == nil {
			shortCode = code
			break
		}
		h.logger.Warn("short code collision, retrying", zap.String("code", code), zap.Error(dbErr))
	}

	resp := map[string]any{
		"url":        portalURL,
		"expires_at": exp.Format(time.RFC3339),
	}
	if shortCode != "" {
		resp["short_url"] = strings.TrimRight(h.issuer, "/") + "/p/" + shortCode
		resp["short_code"] = shortCode
	}
	writeJSON(w, http.StatusOK, resp)
}

// RedeemShortLink looks up a short code and 302-redirects to the full portal URL.
// GET /p/{code}  — public
func (h *EquityPortalHandler) RedeemShortLink(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if code == "" {
		http.NotFound(w, r)
		return
	}

	link, err := h.ent.PortalShortLink.Query().
		Where(portalshortlink.CodeEQ(code)).
		First(r.Context())
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if time.Now().After(link.ExpiresAt) {
		writeError(w, http.StatusGone, "link_expired", "this portal link has expired", nil)
		return
	}

	// Increment click counter in background; ignore errors.
	go func() {
		_, _ = h.ent.PortalShortLink.UpdateOneID(link.ID).
			AddClicks(1).
			Save(context.Background())
	}()

	portalURL := strings.TrimRight(h.uiBaseURL, "/") + "/equity-holder/?token=" + link.JwtToken
	http.Redirect(w, r, portalURL, http.StatusFound)
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
