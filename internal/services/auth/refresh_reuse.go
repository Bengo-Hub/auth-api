package auth

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent/session"
)

const (
	refreshPrevHashKey  = "prev_refresh_hash"
	refreshRotatedAtKey = "refresh_rotated_at"
	// refreshReuseGrace allows two tabs refreshing at once with the same token: within it a
	// replay is only refused, after it the session is revoked.
	refreshReuseGrace = 60 * time.Second
)

// revokeOnStaleRefreshReuse handles a refresh token that matched no session: when it is the token
// an active session rotated away from more than refreshReuseGrace ago, someone kept a copy, so the
// session is revoked (security audit L3).
func (s *Service) revokeOnStaleRefreshReuse(ctx context.Context, hash string) {
	sess, err := s.entClient.Session.Query().
		Where(session.StatusEQ("active"), func(sel *sql.Selector) {
			sel.Where(sqljson.ValueEQ(session.FieldMetadata, hash, sqljson.Path(refreshPrevHashKey)))
		}).
		First(ctx)
	if err != nil || sess == nil {
		return
	}
	rotated, _ := sess.Metadata[refreshRotatedAtKey].(string)
	at, perr := time.Parse(time.RFC3339, rotated)
	if perr != nil || time.Since(at) <= refreshReuseGrace {
		return
	}
	if err := sess.Update().SetStatus("revoked").SetRevokedAt(time.Now()).SetRevocationReason("refresh_token_reuse").Exec(ctx); err != nil {
		s.logger.Warn("revoke session on refresh token reuse", zap.Error(err))
		return
	}
	s.logger.Warn("refresh token reuse: session revoked", zap.String("session_id", sess.ID.String()), zap.String("user_id", sess.UserID.String()))
}
