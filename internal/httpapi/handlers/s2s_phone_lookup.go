package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nyaruka/phonenumbers"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/services/auth"
)

// lookupDefaultRegion reads a national number ("0712...") as Kenyan, the platform's home market.
const lookupDefaultRegion = "KE"

// normalizeLookupPhone turns "+254712...", "254712..." or "0712..." into E.164. It accepts what
// validateAndNormalizePhone accepts (an international number) and, for this lookup only, an
// international number missing its "+" and a Kenyan national number: a WhatsApp sender id arrives
// without the "+".
func normalizeLookupPhone(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("phone is required")
	}
	if p, err := validateAndNormalizePhone(raw); err == nil {
		return p, nil
	}
	if !strings.HasPrefix(raw, "+") {
		if p, err := validateAndNormalizePhone("+" + raw); err == nil && !strings.HasPrefix(raw, "0") {
			return p, nil
		}
	}
	num, err := phonenumbers.Parse(raw, lookupDefaultRegion)
	if err != nil || !phonenumbers.IsValidNumber(num) {
		return "", errors.New("not a valid phone number")
	}
	return phonenumbers.Format(num, phonenumbers.E164), nil
}

// S2SUserByPhone answers which user holds a phone VERIFIED, and that user's active memberships,
// for platform services (marketflow-api's WhatsApp worker decides whether a sender on the platform
// number is a known user). An unverified phone never matches. Internal service key only.
// GET /api/v1/s2s/users/by-phone?phone=+254712345678
func (h *AuthHandler) S2SUserByPhone(w http.ResponseWriter, r *http.Request) {
	phone, err := normalizeLookupPhone(r.URL.Query().Get("phone"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_phone", err.Error(), nil)
		return
	}
	u, err := h.service.LookupVerifiedPhone(r.Context(), phone)
	if errors.Is(err, auth.ErrPhoneNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no user has this phone verified", nil)
		return
	}
	if err != nil {
		h.logger.Error("s2s phone lookup failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "lookup_failed", "phone lookup failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, u)
}
