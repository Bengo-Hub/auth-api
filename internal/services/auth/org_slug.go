package auth

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrOrgSlugTaken: a new organisation asked for a slug that already exists (or is reserved).
	ErrOrgSlugTaken = errors.New("organisation address already taken")
	// ErrInvalidOrgSlug: a new organisation's slug is not lowercase words joined by hyphens.
	ErrInvalidOrgSlug = errors.New("organisation address must be lowercase letters, numbers and single hyphens")
)

var orgSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// reservedOrgSlugs can never be claimed by self-registration: the platform tenant and its demo,
// and words that read as platform or system areas.
var reservedOrgSlugs = map[string]bool{
	platformTenantSlug: true, "codevertex-demo": true, "codevertex-africa": true,
	"admin": true, "administrator": true, "platform": true, "system": true, "root": true,
	"support": true, "security": true, "api": true, "auth": true, "sso": true, "accounts": true,
	"www": true, "mail": true, "webmail": true, "status": true, "billing": true,
}

// validateNewOrgSlug checks a self-registered organisation's slug before anything is written.
func validateNewOrgSlug(slug string) error {
	s := strings.TrimSpace(slug)
	if s == "" || len(s) > 63 || !orgSlugPattern.MatchString(s) {
		return ErrInvalidOrgSlug
	}
	if reservedOrgSlugs[s] {
		return ErrOrgSlugTaken
	}
	return nil
}
