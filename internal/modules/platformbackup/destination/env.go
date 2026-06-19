package destination

import (
	"context"
	"crypto/sha256"
	"os"
	"runtime"
)

// getenv returns the env var value or fallback when unset/empty.
func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// inheritEnv returns a copy of the current process environment, used as the base
// for rclone invocations so it still finds HOME, CA certificates, proxy settings,
// etc. The ephemeral RCLONE_CONFIG_* backend vars are appended on top.
func inheritEnv() []string {
	src := os.Environ()
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// configFileNul returns the platform null device path passed to `rclone --config`
// so rclone neither reads nor writes any persistent config file — all backend
// settings come from RCLONE_CONFIG_* env vars instead. The production runtime is
// Linux (alpine); the Windows branch keeps local `go build`/dev runs honest.
func configFileNul() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

// SecretKeyCipher derives a stable 32-byte AES-256 key from the SECRET_KEY env var
// (sha256(SECRET_KEY)). It satisfies the Cipher interface used by Store to encrypt
// destination credentials at rest. CandidateKeys also includes a key derived from
// the legacy ENCRYPTION_KEY env var (if set and different) so a future migration of
// the keying material still decrypts existing rows. Never logged.
type SecretKeyCipher struct{}

// NewSecretKeyCipher returns the SECRET_KEY-derived cipher.
func NewSecretKeyCipher() SecretKeyCipher { return SecretKeyCipher{} }

// PrimaryKey returns sha256(SECRET_KEY) — the 32-byte key used to encrypt NEW data.
func (SecretKeyCipher) PrimaryKey(context.Context) []byte {
	sum := sha256.Sum256([]byte(getenv("SECRET_KEY", "")))
	return sum[:]
}

// CandidateKeys returns all decryption keys in priority order (PrimaryKey first).
func (c SecretKeyCipher) CandidateKeys(ctx context.Context) [][]byte {
	keys := [][]byte{c.PrimaryKey(ctx)}
	if alt := os.Getenv("ENCRYPTION_KEY"); alt != "" {
		sum := sha256.Sum256([]byte(alt))
		keys = append(keys, sum[:])
	}
	return keys
}
