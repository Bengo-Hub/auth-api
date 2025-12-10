package mfa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/mfabackupcode"
	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
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

func (s *Service) StartTOTP(ctx context.Context, userID uuid.UUID, email string) (*StartTOTPResponse, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
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

func (s *Service) saveOrUpdateTOTP(ctx context.Context, userID uuid.UUID, secret string) error {
	existing, err := s.entClient.MFATOTPSecret.Query().
		Where(mfatotpsecret.UserID(userID)).
		Only(ctx)
	if err == nil {
		return s.entClient.MFATOTPSecret.UpdateOneID(existing.ID).
			SetSecret(secret).
			SetDigits(6).
			SetPeriod(30).
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
	rec, err := s.entClient.MFATOTPSecret.Query().
		Where(mfatotpsecret.UserID(userID)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("load totp: %w", err)
	}
	ok := totp.Validate(code, rec.Secret)
	if !ok {
		return fmt.Errorf("invalid totp code")
	}
	return s.entClient.MFATOTPSecret.UpdateOneID(rec.ID).
		SetEnabledAt(time.Now()).
		Exec(ctx)
}

func (s *Service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	rec, err := s.entClient.MFATOTPSecret.Query().
		Where(mfatotpsecret.UserID(userID)).
		Only(ctx)
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
