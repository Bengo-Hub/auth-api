package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/bengobox/auth-api/internal/ent"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/ent/predicate"
)

// Rotation grace, as Stripe does it: rotating a credential can keep the replaced one working
// for a while so a developer can roll the new value out without downtime. The replaced
// credential's hash and expiry live in App.metadata under these keys. Only one previous value
// is kept per credential, so rotating again during a grace period ends the older one at once.
const (
	metaPreviousClientSecret = "previous_client_secret"
	metaPreviousKey          = "previous_key"
)

// Defaults used when SetRotationGrace is not called (tests) or is given zero values.
const (
	defaultRotationGrace    = 24 * time.Hour
	defaultMaxRotationGrace = 168 * time.Hour
)

// previousCredential is a credential replaced by a rotation that still works until ExpiresAt.
type previousCredential struct {
	Hash      string    `json:"hash"`
	Prefix    string    `json:"prefix,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// activeAt reports whether the previous credential is still inside its grace period.
func (p previousCredential) activeAt(now time.Time) bool {
	return p.Hash != "" && now.Before(p.ExpiresAt)
}

// previousCredentialFrom reads a grace entry from App metadata. Values read back from the
// database are generic maps, so the entry goes through JSON once to get the typed form.
func previousCredentialFrom(meta map[string]any, key string) (previousCredential, bool) {
	raw, ok := meta[key]
	if !ok || raw == nil {
		return previousCredential{}, false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return previousCredential{}, false
	}
	var p previousCredential
	if err := json.Unmarshal(b, &p); err != nil || p.Hash == "" {
		return previousCredential{}, false
	}
	return p, true
}

// activePreviousCredential returns the grace entry under key when it is still in force.
func activePreviousCredential(meta map[string]any, key string, now time.Time) (previousCredential, bool) {
	p, ok := previousCredentialFrom(meta, key)
	if !ok || !p.activeAt(now) {
		return previousCredential{}, false
	}
	return p, true
}

// withPreviousCredential returns a copy of meta with the grace entry under key set, or
// removed when p is nil. The original map is never changed.
func withPreviousCredential(meta map[string]any, key string, p *previousCredential) map[string]any {
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	if p == nil {
		delete(out, key)
		return out
	}
	out[key] = map[string]any{
		"hash":       p.Hash,
		"prefix":     p.Prefix,
		"expires_at": p.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return out
}

// previousSecretMatches reports whether presented is the app's previous consumer secret and
// that secret is still inside its grace period. The compare is constant time.
func previousSecretMatches(meta map[string]any, presented string, now time.Time) bool {
	p, ok := activePreviousCredential(meta, metaPreviousClientSecret, now)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p.Hash), []byte(hashAPIKey(presented))) == 1
}

// previousKeyHashIs matches apps whose metadata names hash as the previous API key. It is a
// JSONB containment test so the GIN (jsonb_path_ops) index on apps.metadata serves it.
func previousKeyHashIs(hash string) predicate.App {
	doc, _ := json.Marshal(map[string]any{metaPreviousKey: map[string]string{"hash": hash}})
	return predicate.App(func(s *entsql.Selector) {
		s.Where(entsql.P(func(b *entsql.Builder) {
			b.Ident(s.C(entapp.FieldMetadata)).WriteString(" @> ").Arg(string(doc)).WriteString("::jsonb")
		}))
	})
}

// findActiveAppByKeyHash finds the active app whose API key hashes to hash. The current key
// is tried first through the unique key_hash index. Only on a miss does it look for an app
// whose previous key (still in its grace period) has this hash, so valid current keys cost
// one indexed lookup exactly as before. found is false when no app matches.
func findActiveAppByKeyHash(ctx context.Context, client *ent.Client, hash string, now time.Time) (a *ent.App, found bool, err error) {
	a, err = client.App.Query().
		Where(entapp.KeyHashEQ(hash), entapp.StatusEQ(entapp.StatusActive)).
		Only(ctx)
	if err == nil {
		return a, true, nil
	}
	if !ent.IsNotFound(err) {
		return nil, false, err
	}
	a, err = client.App.Query().
		Where(previousKeyHashIs(hash), entapp.StatusEQ(entapp.StatusActive)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if _, ok := activePreviousCredential(a.Metadata, metaPreviousKey, now); !ok {
		return nil, false, nil
	}
	return a, true, nil
}

// rotationRequest is the optional body of the rotate-secret and rotate-token calls.
type rotationRequest struct {
	// GraceHours keeps the replaced credential working for this many hours. Absent means the
	// configured default; 0 ends it immediately.
	GraceHours *float64 `json:"grace_hours,omitempty"`
}

// SetRotationGrace sets the default and the largest grace period a rotation may use
// (AUTH_TOKEN_CLIENT_SECRET_GRACE and AUTH_TOKEN_CLIENT_SECRET_MAX_GRACE).
func (h *AppHandler) SetRotationGrace(def, max time.Duration) {
	h.rotationGrace = def
	h.maxRotationGrace = max
	h.rotationGraceSet = true
}

// rotationGraceLimits returns the configured default and maximum grace periods.
func (h *AppHandler) rotationGraceLimits() (def, max time.Duration) {
	def, max = h.rotationGrace, h.maxRotationGrace
	if !h.rotationGraceSet {
		def = defaultRotationGrace
	}
	if max <= 0 {
		max = defaultMaxRotationGrace
	}
	if def < 0 {
		def = 0
	}
	if def > max {
		def = max
	}
	return def, max
}

// parseRotationGrace reads the grace period asked for in the request body. An empty body
// means the configured default.
func (h *AppHandler) parseRotationGrace(r *http.Request) (time.Duration, error) {
	def, max := h.rotationGraceLimits()
	var req rotationRequest
	if r.Body != nil {
		if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("invalid body")
		}
	}
	if req.GraceHours == nil {
		return def, nil
	}
	hours := *req.GraceHours
	if hours < 0 {
		return 0, fmt.Errorf("grace_hours cannot be negative")
	}
	grace := time.Duration(hours * float64(time.Hour))
	if grace > max {
		return 0, fmt.Errorf("grace_hours cannot be more than %g", max.Hours())
	}
	return grace, nil
}
