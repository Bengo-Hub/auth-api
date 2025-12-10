package password

import (
	"errors"

	sharedhasher "github.com/Bengo-Hub/shared-password-hasher"
	"github.com/bengobox/auth-api/internal/config"
)

// ErrInvalidHash indicates the stored hash cannot be parsed.
var ErrInvalidHash = errors.New("invalid password hash")

// Hasher wraps shared password hasher library.
// NOTE: Configuration parameters (Argon2Time, etc.) are ignored as the shared library
// uses standard parameters. For custom parameters, update the shared library.
type Hasher struct {
	shared *sharedhasher.Hasher
}

// NewHasher constructs a Hasher using the shared password-hasher library.
// The cfg parameter is retained for backwards compatibility but config values
// (Argon2Time, Argon2Memory, etc.) are superseded by the shared library defaults:
// m=65536 (64 MiB), t=3, p=2, keylen=32.
//
// If custom parameters are needed in the future, update the shared library
// and all services will automatically adopt the new parameters.
func NewHasher(cfg config.SecurityConfig) *Hasher {
	return &Hasher{
		shared: sharedhasher.NewHasher(),
	}
}

// Hash creates a new Argon2id hash for the supplied plain text password.
// Uses the shared library implementation for consistency across all BengoBox services.
func (h *Hasher) Hash(password string) (string, error) {
	return h.shared.Hash(password)
}

// Compare verifies that the specified password matches the stored hash.
// Uses constant-time comparison via the shared library.
func (h *Hasher) Compare(hash string, password string) error {
	err := h.shared.Verify(password, hash)
	if err != nil {
		// Convert shared library errors to auth-service error format
		if errors.Is(err, sharedhasher.ErrPasswordMismatch) {
			return errors.New("password mismatch")
		}
		return err
	}
	return nil
}
