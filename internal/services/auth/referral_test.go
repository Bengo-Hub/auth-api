package auth

import (
	"strings"
	"testing"
)

func TestNormalizeReferralCode(t *testing.T) {
	for in, want := range map[string]string{
		"CV-AB12CD34":                   "CV-AB12CD34",
		" CV-AB12CD34 ":                 "CV-AB12CD34",
		"CV-1a2b3c4d":                   "CV-1a2b3c4d",
		"":                              "",
		"AB12CD34":                      "",
		"cv-ab12cd34":                   "",
		"CV-":                           "",
		"CV-AB12<script>":               "",
		"CV-AB 12":                      "",
		"CV-" + strings.Repeat("A", 40): "",
	} {
		if got := NormalizeReferralCode(in); got != want {
			t.Errorf("NormalizeReferralCode(%q) = %q, want %q", in, got, want)
		}
	}
	if !IsPlatformOnlyMetadataKey(MetaReferredByCode) {
		t.Error("only Register may set the referral code on a tenant")
	}
}
