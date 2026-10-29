package auth

import "testing"

func TestSafeOAuthReturnTo(t *testing.T) {
	const issuer = "https://sso.codevertexafrica.com"
	ok := []string{
		"/dashboard",
		"/dashboard/profile?tab=security",
		"https://sso.codevertexafrica.com/api/v1/authorize?client_id=ordering-ui&redirect_uri=x",
		"https://ordering.codevertexafrica.com/urban-loft",
		"https://codevertexafrica.com/student",
	}
	for _, u := range ok {
		if got := SafeOAuthReturnTo(u, issuer); got != u {
			t.Errorf("%q should be kept, got %q", u, got)
		}
	}
	bad := []string{
		"", "   ", "//evil.example/x", "/\\evil.example", "http://ordering.codevertexafrica.com/x",
		"https://evil.example/api/v1/authorize", "https://codevertexafrica.com.evil.example/x",
		"javascript:alert(1)", "https://sso.codevertexafrica.com/x\r\nSet-Cookie: a=b",
	}
	for _, u := range bad {
		if got := SafeOAuthReturnTo(u, issuer); got != "" {
			t.Errorf("%q must be dropped, got %q", u, got)
		}
	}
}

func TestSafeOAuthReturnToTenantHosts(t *testing.T) {
	const issuer = "https://sso.codevertexafrica.com"
	hosts := []string{"alphachinamarket.co.ke", " UrbanEats.theurbanloftcafe.com "}
	for _, u := range []string{
		"https://alphachinamarket.co.ke/alpha-china-market",
		"https://urbaneats.theurbanloftcafe.com/urban-loft/checkout",
	} {
		if got := SafeOAuthReturnTo(u, issuer, hosts...); got != u {
			t.Errorf("tenant host %q should be kept, got %q", u, got)
		}
	}
	for _, u := range []string{
		"https://alphachinamarket.co.ke.evil.example/x",
		"https://evilalphachinamarket.co.ke/x",
		"http://alphachinamarket.co.ke/x",
		"https://theurbanloftcafe.com/x", // only the listed subdomain, not the whole site
	} {
		if got := SafeOAuthReturnTo(u, issuer, hosts...); got != "" {
			t.Errorf("%q must be dropped, got %q", u, got)
		}
	}
	if got := SafeOAuthReturnTo("https://alphachinamarket.co.ke/x", issuer); got != "" {
		t.Errorf("without the configured hosts a tenant domain is not trusted, got %q", got)
	}
}
