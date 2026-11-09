package handlers

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SetPasswordLinker issues a one-time set-password link for a newly created account
// (auth.Service.IssueSetPasswordLink). Kept apart from AuthService so existing test doubles of
// that interface stay as they are.
type SetPasswordLinker interface {
	IssueSetPasswordLink(ctx context.Context, userID uuid.UUID, tenantSlug, serviceID string) (string, error)
}

// WithSetPasswordLinks lets new members' welcome emails carry a set-password link.
func (h *AdminHandler) WithSetPasswordLinks(l SetPasswordLinker) *AdminHandler {
	h.setPassword = l
	return h
}

// WithSetPasswordLinks lets admin-created users' welcome emails carry a set-password link.
func (h *UserHandler) WithSetPasswordLinks(l SetPasswordLinker) *UserHandler {
	h.setPassword = l
	return h
}

// issueSetPasswordLink is the link for a welcome email, or "" when none can be made: the welcome
// then still goes out with the sign-in link, so a failure never blocks creating the account.
func issueSetPasswordLink(ctx context.Context, l SetPasswordLinker, log *zap.Logger, userID uuid.UUID, tenantSlug, serviceID string) string {
	if l == nil {
		return ""
	}
	link, err := l.IssueSetPasswordLink(ctx, userID, tenantSlug, serviceID)
	if err != nil {
		if log != nil {
			log.Warn("set-password link not issued; the welcome keeps the sign-in link", zap.String("user_id", userID.String()), zap.Error(err))
		}
		return ""
	}
	return link
}
