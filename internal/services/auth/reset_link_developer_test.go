package auth

import (
	"strings"
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
)

func TestForDeveloperTenant(t *testing.T) {
	dev, other := developerTenantUseCase, "retail"
	link := buildResetLink(nil, "dev-abc", "", "a@b.test", "tok")

	if got := forDeveloperTenant(&ent.Tenant{UseCase: &dev}, link); !strings.HasSuffix(got, "&for=developer") {
		t.Fatalf("developer tenant link = %q", got)
	}
	if got := forDeveloperTenant(&ent.Tenant{UseCase: &other}, link); got != link {
		t.Fatalf("a business tenant link changed: %q", got)
	}
	if got := forDeveloperTenant(&ent.Tenant{}, link); got != link {
		t.Fatalf("a tenant with no use case changed: %q", got)
	}
	own := "https://app.example.com/dev-abc/auth/reset-password?email=a&token=t"
	if got := forDeveloperTenant(&ent.Tenant{UseCase: &dev}, own); got != own {
		t.Fatalf("a tenant's own app link must stay as is: %q", got)
	}
}
