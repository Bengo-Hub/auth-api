package auth

import "testing"

// A sign-in that names no organisation runs under the client's own home tenant when the client
// has one, never the public demo tenant (20 November 2026: website Google sign-ups became demo
// students and got "Welcome to Codevertex Demo").
func TestOAuthStartSlug(t *testing.T) {
	site := map[string]any{clientTenantSlugKey: "codevertex", clientSelfSignupRoleKey: "student"}
	cases := []struct {
		name, slug string
		meta       map[string]any
		want       string
	}{
		{"named tenant wins", "hadia", site, "hadia"},
		{"client home tenant", "", site, "codevertex"},
		{"client home tenant trimmed", " ", map[string]any{clientTenantSlugKey: " codevertex "}, "codevertex"},
		{"no home tenant falls back to demo", "", map[string]any{}, oauthFallbackTenantSlug},
		{"nil metadata falls back to demo", "", nil, oauthFallbackTenantSlug},
		{"non-string metadata ignored", "", map[string]any{clientTenantSlugKey: 7}, oauthFallbackTenantSlug},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := oauthStartSlug(c.slug, c.meta); got != c.want {
				t.Fatalf("oauthStartSlug(%q) = %q, want %q", c.slug, got, c.want)
			}
		})
	}
}
