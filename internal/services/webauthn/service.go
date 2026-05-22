package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	entuser "github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/webauthncredential"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const sessionTTL = 5 * time.Minute

// Errors returned by the service.
var (
	ErrUserNotFound         = errors.New("user not found")
	ErrNoCredentials        = errors.New("user has no registered WebAuthn credentials")
	ErrSessionExpired       = errors.New("webauthn session expired or not found")
	ErrRegistrationFailed   = errors.New("webauthn registration verification failed")
	ErrAuthenticationFailed = errors.New("webauthn authentication verification failed")
)

// Config holds WebAuthn relying party settings.
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

// Service manages WebAuthn credential registration and authentication.
type Service struct {
	webAuthn *webauthn.WebAuthn
	db       *ent.Client
	redis    *redis.Client
	ns       string // Redis key namespace
	logger   *zap.Logger
}

// New creates a WebAuthn Service.
func New(cfg Config, db *ent.Client, redisClient *redis.Client, redisNS string, logger *zap.Logger) (*Service, error) {
	wc, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}
	return &Service{
		webAuthn: wc,
		db:       db,
		redis:    redisClient,
		ns:       redisNS,
		logger:   logger,
	}, nil
}

// --- Registration ---

// BeginRegistration starts the WebAuthn credential registration ceremony.
// Returns the CredentialCreationOptions to send to the browser and stores
// the session data in Redis.
func (s *Service) BeginRegistration(ctx context.Context, userID uuid.UUID, email, displayName string) (*protocol.CredentialCreation, error) {
	existing, err := s.db.WebAuthnCredential.Query().
		Where(webauthncredential.UserID(userID)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load existing credentials: %w", err)
	}

	wu := &webauthnUser{
		id:          userID,
		name:        email,
		displayName: displayName,
		credentials: entToWebAuthnCredentials(existing),
	}

	creation, sessionData, err := s.webAuthn.BeginRegistration(wu)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	if err := s.saveSession(ctx, regKey(s.ns, userID), sessionData); err != nil {
		return nil, err
	}

	return creation, nil
}

// FinishRegistration completes the registration ceremony.
func (s *Service) FinishRegistration(ctx context.Context, userID uuid.UUID, email, displayName, friendlyName string, r *http.Request) (*ent.WebAuthnCredential, error) {
	sessionData, err := s.loadSession(ctx, regKey(s.ns, userID))
	if err != nil {
		return nil, err
	}

	existing, err := s.db.WebAuthnCredential.Query().
		Where(webauthncredential.UserID(userID)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load existing credentials: %w", err)
	}

	wu := &webauthnUser{
		id:          userID,
		name:        email,
		displayName: displayName,
		credentials: entToWebAuthnCredentials(existing),
	}

	credential, err := s.webAuthn.FinishRegistration(wu, *sessionData, r)
	if err != nil {
		s.logger.Warn("webauthn finish registration failed", zap.Error(err))
		return nil, ErrRegistrationFailed
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	aaguid := fmt.Sprintf("%x", credential.Authenticator.AAGUID)

	create := s.db.WebAuthnCredential.Create().
		SetUserID(userID).
		SetCredentialID(credential.ID).
		SetPublicKey(credential.PublicKey).
		SetAaguid(aaguid).
		SetSignCount(credential.Authenticator.SignCount).
		SetUserVerified(credential.Flags.UserVerified).
		SetBackupEligible(credential.Flags.BackupEligible).
		SetBackupState(credential.Flags.BackupState)

	if len(transports) > 0 {
		create = create.SetTransports(transports)
	}
	if friendlyName != "" {
		create = create.SetFriendlyName(friendlyName)
	}

	saved, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("save webauthn credential: %w", err)
	}

	_ = s.redis.Del(ctx, regKey(s.ns, userID))
	return saved, nil
}

// --- Authentication ---

// BeginAuthentication starts the WebAuthn authentication ceremony.
// Returns the assertion options, the Redis session key (passed back in FinishAuthentication), and an error.
func (s *Service) BeginAuthentication(ctx context.Context, email string) (*protocol.CredentialAssertion, string, error) {
	var (
		assertion   *protocol.CredentialAssertion
		sessionData *webauthn.SessionData
		err         error
		sessionKey  string
	)

	if email == "" {
		// Discoverable / passkey login — browser will present its own credential picker.
		sessionKey = authKey(s.ns, uuid.New().String())
		assertion, sessionData, err = s.webAuthn.BeginDiscoverableLogin()
	} else {
		sessionKey = authKey(s.ns, email)
		userEntity, err2 := s.db.User.Query().
			Where(entuser.Email(email)).
			First(ctx)
		if err2 != nil {
			if ent.IsNotFound(err2) {
				return nil, "", ErrUserNotFound
			}
			return nil, "", fmt.Errorf("query user: %w", err2)
		}

		creds, err2 := s.db.WebAuthnCredential.Query().
			Where(webauthncredential.UserID(userEntity.ID)).
			All(ctx)
		if err2 != nil {
			return nil, "", fmt.Errorf("load credentials: %w", err2)
		}
		if len(creds) == 0 {
			return nil, "", ErrNoCredentials
		}

		wu := &webauthnUser{
			id:          userEntity.ID,
			name:        userEntity.Email,
			displayName: userEntity.Email,
			credentials: entToWebAuthnCredentials(creds),
		}
		assertion, sessionData, err = s.webAuthn.BeginLogin(wu)
	}

	if err != nil {
		return nil, "", fmt.Errorf("begin authentication: %w", err)
	}

	if err := s.saveSession(ctx, sessionKey, sessionData); err != nil {
		return nil, "", err
	}

	return assertion, sessionKey, nil
}

// FinishAuthentication completes the WebAuthn authentication ceremony.
// Returns the authenticated user's UUID on success.
func (s *Service) FinishAuthentication(ctx context.Context, sessionKey string, r *http.Request) (uuid.UUID, error) {
	sessionData, err := s.loadSession(ctx, sessionKey)
	if err != nil {
		return uuid.Nil, err
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse credential response: %w", err)
	}

	// Find credential by raw ID to identify the user.
	credEntity, err := s.db.WebAuthnCredential.Query().
		Where(webauthncredential.CredentialID(parsedResponse.RawID)).
		WithUser().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return uuid.Nil, ErrAuthenticationFailed
		}
		return uuid.Nil, fmt.Errorf("find credential: %w", err)
	}

	userEntity := credEntity.Edges.User
	if userEntity == nil {
		return uuid.Nil, ErrAuthenticationFailed
	}

	// Load all user credentials for validation.
	allCreds, err := s.db.WebAuthnCredential.Query().
		Where(webauthncredential.UserID(userEntity.ID)).
		All(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("load user credentials: %w", err)
	}

	wu := &webauthnUser{
		id:          userEntity.ID,
		name:        userEntity.Email,
		displayName: userEntity.Email,
		credentials: entToWebAuthnCredentials(allCreds),
	}

	_, err = s.webAuthn.ValidateLogin(wu, *sessionData, parsedResponse)
	if err != nil {
		s.logger.Warn("webauthn authentication failed", zap.Error(err))
		return uuid.Nil, ErrAuthenticationFailed
	}

	now := time.Now()
	_ = s.db.WebAuthnCredential.UpdateOneID(credEntity.ID).
		SetLastUsedAt(now).
		Exec(ctx)

	_ = s.redis.Del(ctx, sessionKey)
	return userEntity.ID, nil
}

// ListCredentials returns all registered WebAuthn credentials for a user.
func (s *Service) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*ent.WebAuthnCredential, error) {
	return s.db.WebAuthnCredential.Query().
		Where(webauthncredential.UserID(userID)).
		Order(ent.Asc(webauthncredential.FieldCreatedAt)).
		All(ctx)
}

// DeleteCredential removes a specific WebAuthn credential belonging to the given user.
func (s *Service) DeleteCredential(ctx context.Context, userID, credentialID uuid.UUID) error {
	n, err := s.db.WebAuthnCredential.Delete().
		Where(
			webauthncredential.ID(credentialID),
			webauthncredential.UserID(userID),
		).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// --- Redis helpers ---

func (s *Service) saveSession(ctx context.Context, key string, data *webauthn.SessionData) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal webauthn session: %w", err)
	}
	return s.redis.Set(ctx, key, b, sessionTTL).Err()
}

func (s *Service) loadSession(ctx context.Context, key string) (*webauthn.SessionData, error) {
	b, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionExpired
		}
		return nil, fmt.Errorf("load webauthn session: %w", err)
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("unmarshal webauthn session: %w", err)
	}
	return &data, nil
}

func regKey(ns string, userID uuid.UUID) string {
	return fmt.Sprintf("%s:webauthn:reg:%s", ns, userID.String())
}

func authKey(ns, id string) string {
	return fmt.Sprintf("%s:webauthn:auth:%s", ns, id)
}

// --- webauthnUser implements webauthn.User ---

type webauthnUser struct {
	id          uuid.UUID
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	b, _ := u.id.MarshalBinary()
	return b
}
func (u *webauthnUser) WebAuthnName() string                      { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string               { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
func (u *webauthnUser) WebAuthnIcon() string                      { return "" }

// entToWebAuthnCredentials converts ent entities to go-webauthn Credential slice.
func entToWebAuthnCredentials(creds []*ent.WebAuthnCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
			Transport: transports,
			Flags: webauthn.CredentialFlags{
				UserVerified:   c.UserVerified,
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
		})
	}
	return out
}
