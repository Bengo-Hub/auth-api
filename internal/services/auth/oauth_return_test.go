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
