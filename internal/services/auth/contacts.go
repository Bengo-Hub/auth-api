package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/useremail"
	"github.com/bengobox/auth-api/internal/ent/userphone"
)

var (
	ErrPhoneAlreadyExists = errors.New("user with phone already exists")
	ErrContactNotFound    = errors.New("contact not found")
)

// ListUserEmails returns every registered email address for a user (their
// primary User.email column is NOT included here — callers that need the
// full picture combine this with GetUser — this list is only the additional
// UserEmail rows, matching Zoho's "My Email Addresses" model).
func (s *Service) ListUserEmails(ctx context.Context, userID uuid.UUID) ([]*ent.UserEmail, error) {
	return s.entClient.UserEmail.Query().
		Where(useremail.UserIDEQ(userID)).
		Order(ent.Asc(useremail.FieldCreatedAt)).
		All(ctx)
}

// AddVerifiedUserEmail creates a new, already-OTP-proven secondary email for
// a user. Mirrors VerifyAndSetUserEmail's uniqueness check but does NOT
// touch the primary User.email column — this is strictly an ADDITIONAL
// address, unlike VerifyAndSetUserEmail's "replace the placeholder" job.
func (s *Service) AddVerifiedUserEmail(ctx context.Context, userID uuid.UUID, email string) (*ent.UserEmail, error) {
	email = normalizeEmail(email)
	if s.EmailTakenByOther(ctx, email, userID) {
		return nil, ErrEmailAlreadyExists
	}
	if taken, err := s.entClient.UserEmail.Query().Where(useremail.EmailEQ(email)).Exist(ctx); err == nil && taken {
		return nil, ErrEmailAlreadyExists
	}
	now := time.Now()
	created, err := s.entClient.UserEmail.Create().
		SetUserID(userID).
		SetEmail(email).
		SetIsVerified(true).
		SetVerifiedAt(now).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, err
	}
	return created, nil
}

// SetPrimaryUserEmail flips is_primary on the given row and clears it on
// every other row for the same user — done as two writes rather than a DB
// partial-unique-index (this is a low-contention, single-user-initiated
// action, not a hot path needing that hardening).
func (s *Service) SetPrimaryUserEmail(ctx context.Context, userID, emailID uuid.UUID) error {
	row, err := s.entClient.UserEmail.Get(ctx, emailID)
	if err != nil || row.UserID != userID {
		return ErrContactNotFound
	}
	if _, err := s.entClient.UserEmail.Update().
		Where(useremail.UserIDEQ(userID), useremail.IsPrimaryEQ(true)).
		SetIsPrimary(false).
		Save(ctx); err != nil {
		return err
	}
	_, err = row.Update().SetIsPrimary(true).Save(ctx)
	return err
}

// DeleteUserEmail removes a secondary email, scoped to its owner.
func (s *Service) DeleteUserEmail(ctx context.Context, userID, emailID uuid.UUID) error {
	n, err := s.entClient.UserEmail.Delete().
		Where(useremail.IDEQ(emailID), useremail.UserIDEQ(userID)).
		Exec(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrContactNotFound
	}
	return nil
}

// --- Phone numbers: same shape, but this platform has no SMS-OTP provider
// wired anywhere yet, so these are added as unverified contact info only
// (is_verified stays false) — see project_sso_accounts_portal_revamp.md
// for why real verification is out of scope for this pass. ---

func (s *Service) ListUserPhones(ctx context.Context, userID uuid.UUID) ([]*ent.UserPhone, error) {
	return s.entClient.UserPhone.Query().
		Where(userphone.UserIDEQ(userID)).
		Order(ent.Asc(userphone.FieldCreatedAt)).
		All(ctx)
}

func (s *Service) AddUserPhone(ctx context.Context, userID uuid.UUID, phone string) (*ent.UserPhone, error) {
	created, err := s.entClient.UserPhone.Create().
		SetUserID(userID).
		SetPhone(phone).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrPhoneAlreadyExists
		}
		return nil, err
	}
	return created, nil
}

func (s *Service) SetPrimaryUserPhone(ctx context.Context, userID, phoneID uuid.UUID) error {
	row, err := s.entClient.UserPhone.Get(ctx, phoneID)
	if err != nil || row.UserID != userID {
		return ErrContactNotFound
	}
	if _, err := s.entClient.UserPhone.Update().
		Where(userphone.UserIDEQ(userID), userphone.IsPrimaryEQ(true)).
		SetIsPrimary(false).
		Save(ctx); err != nil {
		return err
	}
	_, err = row.Update().SetIsPrimary(true).Save(ctx)
	return err
}

func (s *Service) DeleteUserPhone(ctx context.Context, userID, phoneID uuid.UUID) error {
	n, err := s.entClient.UserPhone.Delete().
		Where(userphone.IDEQ(phoneID), userphone.UserIDEQ(userID)).
		Exec(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrContactNotFound
	}
	return nil
}
