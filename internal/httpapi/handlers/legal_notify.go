package handlers

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/platform/outbox"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Email notice of a material Terms of Service or Privacy Policy change (owner 2026-11-15, as in
// Hadia). auth-api owns the users, so it fans out one auth.legal.updated.notify event per active
// user with a real mailbox; notifications-api sends the email, keyed per user and version so a
// rerun never mails anyone twice.

// legalNotifyBatch is how many users one outbox transaction covers.
const legalNotifyBatch = 500

// legalPublicPaths are auth-ui's public pages of the consent types.
var legalPublicPaths = map[string]string{
	DocTypeTermsOfService: "/terms-of-service",
	DocTypePrivacyPolicy:  "/privacy",
}

// legalConsentTitles name a consent type when its version has no title.
var legalConsentTitles = map[string]string{
	DocTypeTermsOfService: "Terms of Service",
	DocTypePrivacyPolicy:  "Privacy Policy",
}

// WithPublicSite sets auth-ui's base URL for the links in a legal change notice.
func (h *LegalHandler) WithPublicSite(base string) *LegalHandler {
	h.publicSite = strings.TrimRight(strings.TrimSpace(base), "/")
	return h
}

// startChangeNotice mails every user about a material consent version, in the background so the
// publish answers at once. It is a no-op for any other version.
func (h *LegalHandler) startChangeNotice(doc *ent.LegalDocument) {
	if !isUserConsent(string(doc.DocType)) || !docMaterial(doc) || doc.Status != "published" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		n, err := h.notifyUsersOfChange(ctx, doc)
		if err != nil {
			h.logger.Error("legal change notice stopped part way", zap.String("doc_type", string(doc.DocType)),
				zap.String("version", doc.Version), zap.Int("queued", n), zap.Error(err))
			return
		}
		h.logger.Info("legal change notice queued", zap.String("doc_type", string(doc.DocType)),
			zap.String("version", doc.Version), zap.Int("users", n))
	}()
}

// legalChangeNoticeData is the event payload for one user.
func (h *LegalHandler) legalChangeNoticeData(doc *ent.LegalDocument, u *ent.User) map[string]any {
	title, _ := doc.Metadata["title"].(string)
	if title == "" {
		title = legalConsentTitles[string(doc.DocType)]
	}
	summary, _ := doc.Metadata["summary"].(string)
	name := profileStr(u.Profile, "name")
	if name == "" {
		name = u.Email
	}
	link := ""
	if h.publicSite != "" {
		link = h.publicSite + legalPublicPaths[string(doc.DocType)] + "/" + url.PathEscape(doc.Version)
	}
	return map[string]any{
		"email":          u.Email,
		"name":           name,
		"user_id":        u.ID.String(),
		"doc_type":       string(doc.DocType),
		"title":          title,
		"version":        doc.Version,
		"summary":        summary,
		"effective_date": doc.EffectiveDate.UTC().Format(time.DateOnly),
		"in_force":       !doc.EffectiveDate.After(time.Now()),
		"document_url":   link,
	}
}

// notifyUsersOfChange writes the events in batches, walking users by id so a large table is read
// in steps and never held in memory. It returns how many users were queued.
func (h *LegalHandler) notifyUsersOfChange(ctx context.Context, doc *ent.LegalDocument) (int, error) {
	total := 0
	var after uuid.UUID
	for {
		q := h.ent.User.Query().
			Where(user.StatusEQ("active"), user.EmailNEQ("")).
			Order(ent.Asc(user.FieldID)).
			Limit(legalNotifyBatch)
		if after != uuid.Nil {
			q = q.Where(user.IDGT(after))
		}
		users, err := q.All(ctx)
		if err != nil {
			return total, err
		}
		if len(users) == 0 {
			return total, nil
		}
		after = users[len(users)-1].ID

		tx, err := h.ent.Tx(ctx)
		if err != nil {
			return total, err
		}
		queued := 0
		for _, u := range users {
			if auth.IsPlaceholderEmail(u.Email) {
				continue
			}
			tenantID, _ := uuid.Parse(u.PrimaryTenantID)
			if err := outbox.Write(ctx, tx.Client(), tenantID, "auth.legal", u.ID, "updated.notify", "",
				h.legalChangeNoticeData(doc, u)); err != nil {
				_ = tx.Rollback()
				return total, err
			}
			queued++
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += queued
		if len(users) < legalNotifyBatch {
			return total, nil
		}
	}
}
