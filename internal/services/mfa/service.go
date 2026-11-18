package mfa

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/mfabackupcode"
	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Service provides TOTP MFA enrollment and verification.
type Service struct {
	entClient *ent.Client
	issuer    string
}

func New(entClient *ent.Client, issuer string) *Service {
	return &Service{entClient: entClient, issuer: issuer}
}

type StartTOTPResponse struct {
	Secret       string
	Provisioning string
}

// ErrAuthenticatorExists is returned when an authenticator is already enabled and the caller did not
// prove its current code (or may not replace it at all, as an enrolment-only session may not).
var ErrAuthenticatorExists = errors.New("an authenticator app is already set up")

// ErrInvalidCode is returned when a code does not match the authenticator.
var ErrInvalidCode = errors.New("invalid totp code")

// sessionMetadataMFAEnrollment marks an enrolment-only session (auth.sessionMetadataMFAEnrollment).
const sessionMetadataMFAEnrollment = "mfa_enrollment_required"

// StartTOTP creates a new secret for the user. When an authenticator is already enabled it is
// replaced only after currentCode proves it: a session alone, or a password alone (an
// enrolment-only session), must never be able to swap the second factor of an account that has
// one. A replacement clears enabled_at until the new code is confirmed.
func (s *Service) StartTOTP(ctx context.Context, userID uuid.UUID, email, currentCode string) (*StartTOTPResponse, error) {
	existing, err := s.loadTOTP(ctx, userID)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("load totp: %w", err)
	}
	opts := totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	}
	switch {
	case existing != nil && !existing.EnabledAt.IsZero():
		if strings.TrimSpace(currentCode) == "" {
			return nil, ErrAuthenticatorExists
		}
		if !totp.Validate(strings.TrimSpace(currentCode), existing.Secret) {
			return nil, ErrInvalidCode
		}
	case existing != nil:
		// Setup already started and not confirmed: hand back the same secret. A second start (the
		// page rendering twice, a double tap, a refresh) used to replace it, so the QR the person
		// scanned no longer matched and every code failed; they were sent to scan again at sign-in.
		if raw, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(existing.Secret)); decErr == nil {
			opts.Secret = raw
			key, genErr := totp.Generate(opts)
			if genErr == nil && key.Secret() == existing.Secret {
				return &StartTOTPResponse{Secret: existing.Secret, Provisioning: key.URL()}, nil
			}
		}
		opts.Secret = nil // unreadable pending secret: replace it below
	}
	key, err := totp.Generate(opts)
	if err != nil {
		return nil, fmt.Errorf("generate totp: %w", err)
	}
	secret := key.Secret()
	// insert secret; if exists, update fields
	if err := s.saveOrUpdateTOTP(ctx, userID, secret); err != nil {
		return nil, err
	}
	return &StartTOTPResponse{
		Secret:       secret,
		Provisioning: key.URL(),
	}, nil
}

// loadTOTP returns the account's authenticator row. Two concurrent first starts could create two
// rows (user_id has no unique index), and every Only() lookup then failed for good; the extra rows
// are removed here, keeping an enabled one first, else the newest.
func (s *Service) loadTOTP(ctx context.Context, userID uuid.UUID) (*ent.MFATOTPSecret, error) {
	rows, err := s.entClient.MFATOTPSecret.Query().
		Where(mfatotpsecret.UserID(userID)).
		Order(ent.Desc(mfatotpsecret.FieldEnabledAt), ent.Desc(mfatotpsecret.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, &ent.NotFoundError{}
	}
	keep := rows[0]
	for _, r := range rows {
		if !r.EnabledAt.IsZero() && (keep.EnabledAt.IsZero() || r.EnabledAt.After(keep.EnabledAt)) {
			keep = r
		}
	}
	if len(rows) > 1 {
		if _, delErr := s.entClient.MFATOTPSecret.Delete().
			Where(mfatotpsecret.UserID(userID), mfatotpsecret.IDNEQ(keep.ID)).
			Exec(ctx); delErr != nil {
			return nil, fmt.Errorf("remove duplicate totp rows: %w", delErr)
		}
	}
	return keep, nil
}

func (s *Service) saveOrUpdateTOTP(ctx context.Context, userID uuid.UUID, secret string) error {
	existing, err := s.loadTOTP(ctx, userID)
	if err == nil {
		return s.entClient.MFATOTPSecret.UpdateOneID(existing.ID).
			SetSecret(secret).
			SetDigits(6).
			SetPeriod(30).
			ClearEnabledAt().
			Exec(ctx)
	}
	_, err = s.entClient.MFATOTPSecret.Create().
		SetUserID(userID).
		SetSecret(secret).
		SetDigits(6).
		SetPeriod(30).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("save totp secret: %w", err)
	}
	return nil
}

func (s *Service) ConfirmTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	rec, err := s.loadTOTP(ctx, userID)
	if err != nil {
		return fmt.Errorf("load totp: %w", err)
	}
	ok := totp.Validate(strings.TrimSpace(code), rec.Secret)
	if !ok {
		return ErrInvalidCode
	}
	return s.entClient.MFATOTPSecret.UpdateOneID(rec.ID).
		SetEnabledAt(time.Now()).
		Exec(ctx)
}

// RevokeOtherEnrollmentSessions ends the user's enrolment-only sessions other than keep, once an
// authenticator is confirmed. An enrolment-only session is what a password alone buys on a covered
// account, so none may outlive the moment the account gains its second factor.
func (s *Service) RevokeOtherEnrollmentSessions(ctx context.Context, userID uuid.UUID, keep uuid.UUID) (int, error) {
	sessions, err := s.entClient.Session.Query().
		Where(session.UserID(userID), session.StatusEQ("active")).
		All(ctx)
	if err != nil {
		return 0, fmt.Errorf("load sessions: %w", err)
	}
	revoked := 0
	for _, sess := range sessions {
		if sess.ID == keep {
			continue
		}
		if flag, _ := sess.Metadata[sessionMetadataMFAEnrollment].(bool); !flag {
			continue
		}
		if err := s.entClient.Session.UpdateOneID(sess.ID).
			SetStatus("revoked").
			SetRevokedAt(time.Now()).
			Exec(ctx); err != nil {
			return revoked, fmt.Errorf("revoke session: %w", err)
		}
		revoked++
	}
	return revoked, nil
}

// HasUnusedBackupCodes reports whether the user holds any backup code not yet used.
func (s *Service) HasUnusedBackupCodes(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.entClient.MFABackupCode.Query().
		Where(mfabackupcode.UserID(userID), mfabackupcode.UsedAtIsNil()).
		Exist(ctx)
}

func (s *Service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	rec, err := s.loadTOTP(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("load totp: %w", err)
	}
	ok := totp.Validate(code, rec.Secret)
	if ok {
		_ = s.entClient.MFATOTPSecret.UpdateOneID(rec.ID).
			SetLastUsedAt(time.Now()).
			Exec(ctx)
	}
	return ok, nil
}

func (s *Service) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}
	// delete old
	if _, err := s.entClient.MFABackupCode.Delete().Where(mfabackupcode.UserID(userID)).Exec(ctx); err != nil {
		return nil, fmt.Errorf("clear old codes: %w", err)
	}
	var plain []string
	for i := 0; i < count; i++ {
		code := uuid.NewString()
		sum := sha256.Sum256([]byte(code))
		if _, err := s.entClient.MFABackupCode.Create().
			SetUserID(userID).
			SetCodeHash(hex.EncodeToString(sum[:])).
			Save(ctx); err != nil {
			return nil, fmt.Errorf("save backup code: %w", err)
		}
		plain = append(plain, code)
	}
	return plain, nil
}

func (s *Service) ConsumeBackupCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	sum := sha256.Sum256([]byte(code))
	rec, err := s.entClient.MFABackupCode.
		Query().
		Where(
			mfabackupcode.UserID(userID),
			mfabackupcode.CodeHashEQ(hex.EncodeToString(sum[:])),
			mfabackupcode.UsedAtIsNil(),
		).Only(ctx)
	if err != nil {
		return false, nil
	}
	if err := s.entClient.MFABackupCode.UpdateOneID(rec.ID).
		SetUsedAt(time.Now()).
		Exec(ctx); err != nil {
		return false, fmt.Errorf("mark used: %w", err)
	}
	return true, nil
}
