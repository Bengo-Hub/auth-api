package handlers

import (
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/referrallink"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ReferralLinkHandler manages auth-side referral link tracking.
type ReferralLinkHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

func NewReferralLinkHandler(entClient *ent.Client, logger *zap.Logger) *ReferralLinkHandler {
	return &ReferralLinkHandler{ent: entClient, logger: logger.Named("referral_links")}
}

// GetLinkByCode validates a referral code and increments click counter.
// GET /api/v1/referrals/link/{code}
func (h *ReferralLinkHandler) GetLinkByCode(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing_code", "referral code is required", nil)
		return
	}

	ctx := r.Context()
	link, err := h.ent.ReferralLink.Query().
		Where(referrallink.ReferralCodeEQ(code), referrallink.IsActiveEQ(true)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "referral link not found or inactive", nil)
			return
		}
		h.logger.Error("failed to fetch referral link", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to fetch referral link", nil)
		return
	}

	if link.ExpiresAt != nil && link.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusGone, "expired", "referral link has expired", nil)
		return
	}

	// Increment click counter.
	if err := h.ent.ReferralLink.UpdateOneID(link.ID).
		SetClicks(link.Clicks + 1).
		Exec(ctx); err != nil {
		h.logger.Warn("failed to increment referral link clicks", zap.Error(err))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"referral_code": link.ReferralCode,
		"program_id":    link.ProgramID,
		"clicks":        link.Clicks + 1,
	})
}

// CreateReferralLink creates a new referral link for the authed tenant.
// POST /api/v1/admin/referral-links
func (h *ReferralLinkHandler) CreateReferralLink(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
		return
	}

	var req struct {
		ProgramID string  `json:"program_id"`
		ExpiresAt *string `json:"expires_at"` // RFC3339 or null
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}

	code := generateReferralCode()

	create := h.ent.ReferralLink.Create().
		SetReferrerTenantID(tenantID).
		SetReferralCode(code).
		SetProgramID(req.ProgramID).
		SetIsActive(true).
		SetClicks(0)

	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_date", "expires_at must be RFC3339", nil)
			return
		}
		create.SetExpiresAt(exp)
	}

	link, err := create.Save(r.Context())
	if err != nil {
		h.logger.Error("failed to create referral link", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create referral link", nil)
		return
	}

	writeJSON(w, http.StatusCreated, toReferralLinkResponse(link))
}

// ListReferralLinks returns all referral links for the authed tenant.
// GET /api/v1/admin/referral-links
func (h *ReferralLinkHandler) ListReferralLinks(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
		return
	}

	links, err := h.ent.ReferralLink.Query().
		Where(referrallink.ReferrerTenantIDEQ(tenantID)).
		Order(ent.Desc(referrallink.FieldCreatedAt)).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to list referral links", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list referral links", nil)
		return
	}

	resp := make([]map[string]any, 0, len(links))
	for _, l := range links {
		resp = append(resp, toReferralLinkResponse(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"referral_links": resp})
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func toReferralLinkResponse(l *ent.ReferralLink) map[string]any {
	m := map[string]any{
		"id":                 l.ID.String(),
		"referrer_tenant_id": l.ReferrerTenantID.String(),
		"referral_code":      l.ReferralCode,
		"program_id":         l.ProgramID,
		"clicks":             l.Clicks,
		"is_active":          l.IsActive,
		"created_at":         l.CreatedAt.Format(time.RFC3339),
	}
	if l.ExpiresAt != nil {
		m["expires_at"] = l.ExpiresAt.Format(time.RFC3339)
	}
	return m
}

// generateReferralCode produces a short alphanumeric code like "CVBK-XKQP".
func generateReferralCode() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[uuid.New().ID()%uint32(len(chars))]
	}
	return string(b[:4]) + "-" + string(b[4:])
}
