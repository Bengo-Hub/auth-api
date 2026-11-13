package auth

import "strings"

// MetaReferredByCode is the tenant metadata key holding the gift a friend code the
// organisation signed up with (platform only, set by Register).
const MetaReferredByCode = "referred_by_code"

// NormalizeReferralCode returns a referral code trimmed, or "" when it is not one:
// subscriptions-api codes are "CV-" and letters or digits (its fallback codes are lower case
// hex, so the case is kept as given). A malformed code is dropped quietly, so a mangled link
// never blocks a sign-up.
func NormalizeReferralCode(raw string) string {
	c := strings.TrimSpace(raw)
	if len(c) < 6 || len(c) > 32 || !strings.HasPrefix(c, "CV-") {
		return ""
	}
	for _, r := range c[3:] {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return c
}
