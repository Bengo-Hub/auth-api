// Package sessionlimit caps how many sessions one person keeps per app.
package sessionlimit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/predicate"
	"github.com/bengobox/auth-api/internal/ent/session"
)

// RevocationReason marks a session ended by the limit; the cleanup job purges it like any revoked one.
const RevocationReason = "session_limit"

func sameClient(clientID string) predicate.Session {
	if clientID == "" {
		// Portal sign-ins carry no client: stored as an empty string or left unset.
		return session.Or(session.ClientIDIsNil(), session.ClientIDEQ(""))
	}
	return session.ClientIDEQ(clientID)
}

// Enforce ends a person's sessions in one app beyond the keep most recently used, and returns how
// many it ended. Every refresh touches updated_at, so a device in daily use is never the one ended.
// keep of zero or less turns the limit off.
func Enforce(ctx context.Context, client *ent.Client, userID uuid.UUID, clientID string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	excess, err := client.Session.Query().
		Where(
			session.UserIDEQ(userID),
			session.SessionTypeEQ("user"),
			session.StatusEQ("active"),
			sameClient(clientID),
		).
		Order(ent.Desc(session.FieldUpdatedAt), ent.Desc(session.FieldID)).
		Offset(keep).
		IDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("find sessions over the limit: %w", err)
	}
	if len(excess) == 0 {
		return 0, nil
	}
	ended, err := client.Session.Update().
		Where(session.IDIn(excess...), session.StatusEQ("active")).
		SetStatus("revoked").
		SetRevokedAt(time.Now()).
		SetRevocationReason(RevocationReason).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("end sessions over the limit: %w", err)
	}
	return ended, nil
}
