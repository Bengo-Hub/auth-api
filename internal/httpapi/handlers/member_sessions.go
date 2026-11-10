package handlers

import (
	"context"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/session"
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
