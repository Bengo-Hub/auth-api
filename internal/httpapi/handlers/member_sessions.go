package handlers

import (
	"context"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
)

// revokeMemberSessions ends a member's active sessions in one tenant, for when an admin removes
// or suspends them (audit H2). Sessions in their other tenants stay. Returns how many ended;
// failures are reported as 0 and the next refresh is refused anyway (no active membership).
func revokeMemberSessions(ctx context.Context, client *ent.Client, tenantID, userID uuid.UUID) int {
	n, err := client.Session.Update().
		Where(session.UserID(userID), session.TenantID(tenantID), session.StatusEQ("active")).
		SetStatus("revoked").
		Save(ctx)
	if err != nil {
		return 0
	}
	return n
}

// memberReAddRefused reports whether adding an existing member again must be refused: anything
// but an active membership (suspended, deactivated, inactive) is reactivated only explicitly.
func memberReAddRefused(status string) bool {
	return status != "" && status != "active"
}

// accountOnlyInTenant reports whether the account belongs to no tenant other than tenantID. A
// tenant admin may set a sign-in phone only on such an account (audit H3); anyone else adds
// their own phone, verified by code.
func accountOnlyInTenant(ctx context.Context, client *ent.Client, userID, tenantID uuid.UUID) bool {
	n, err := client.TenantMembership.Query().
		Where(tenantmembership.UserID(userID), tenantmembership.TenantIDNEQ(tenantID)).
		Count(ctx)
	return err == nil && n == 0
}
