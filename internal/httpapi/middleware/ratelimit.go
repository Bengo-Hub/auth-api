package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	ratelimit "github.com/Bengo-Hub/shared-ratelimit"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RateLimits holds auth-api's request limits, built on shared-ratelimit (GCRA in Redis, exact
// across every replica, per-pod fallback while Redis is down). It replaces the local
// fixed-window limiter, which keyed on a client-spoofable RemoteAddr, allowed a 2x burst at
// every window edge and returned 429 for every login whenever Redis hiccuped.
type RateLimits struct {
	l *ratelimit.Limiter
}

// NewRateLimits creates the limiter set. namespace keeps keys apart from other services.
func NewRateLimits(rdb redis.UniversalClient, log *zap.Logger, namespace string) *RateLimits {
	if namespace == "" {
		namespace = "auth"
	}
	return &RateLimits{l: ratelimit.NewLimiter(rdb, log, namespace)}
}

// Login limits password login three ways: per client IP (general abuse), per IP and target
// account (one source guessing one password), and per target account across all IPs (a
// distributed guess against one user). The account caps are the per-account lockout: a
// legitimate user who mistypes a few times is never affected, a brute force stalls after
// 10 guesses per IP per 15 minutes and 30 per hour in total.
func (rl *RateLimits) Login() func(http.Handler) http.Handler {
	perIP := rl.l.MiddlewareWith(ratelimit.IPKey, ratelimit.Options{Name: "login-ip", Limit: 60, Window: time.Minute})
	perIPAccount := rl.l.MiddlewareWith(ratelimit.CompositeKey(ratelimit.IPKey, accountKey), ratelimit.Options{Name: "login-ip-acct", Limit: 10, Window: 15 * time.Minute})
	perAccount := rl.l.MiddlewareWith(accountKey, ratelimit.Options{Name: "login-acct", Limit: 30, Window: time.Hour})
	return func(next http.Handler) http.Handler {
		return perIP(perIPAccount(perAccount(next)))
	}
}

// Token limits refresh and token exchange per client IP.
func (rl *RateLimits) Token() func(http.Handler) http.Handler {
	return rl.l.MiddlewareWith(ratelimit.IPKey, ratelimit.Options{Name: "token", Limit: 120, Window: time.Minute})
}

// Sensitive limits unauthenticated code and account flows (send/verify email code, password
// reset, registration) per client IP. The handlers also cap sends and wrong guesses per code.
func (rl *RateLimits) Sensitive() func(http.Handler) http.Handler {
	return rl.l.MiddlewareWith(ratelimit.IPKey, ratelimit.Options{Name: "sensitive", Limit: 20, Window: time.Minute})
}

// accountKey reads the login identifier from a JSON body without consuming it. Returns "" (no
// account limit) when the body has no email, so the IP limit still applies.
func accountKey(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	orig := r.Body
	raw, err := io.ReadAll(io.LimitReader(orig, 64<<10))
	// Replay what was peeked, then the rest of the original stream, so the handler always sees
	// the complete body.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(raw), orig), orig}
	if err != nil {
		return ""
	}
	var body struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	id := strings.ToLower(strings.TrimSpace(body.Email))
	if id == "" {
		id = strings.ToLower(strings.TrimSpace(body.Username))
	}
	if id == "" {
		return ""
	}
	return "acct:" + id
}
