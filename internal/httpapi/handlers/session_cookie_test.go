package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/token"
)

const testAppOrigin = "https://pos.codevertexafrica.com"

// sessionCookieFake rotates refresh tokens and applies the reuse rules the way the service does
// (refresh_reuse.go): a replayed old token is refused, and revokes the session once it is older
// than the 60s grace.
type sessionCookieFake struct {
	AuthService
	now          time.Time
	next         int
	active       map[string]uuid.UUID
	rotated      map[string]sessionRotation
	revoked      map[uuid.UUID]bool
	refreshCalls int
	loggedOutJTI string
}

type sessionRotation struct {
	sid uuid.UUID
	at  time.Time
}

func newSessionCookieFake(seed string) (*sessionCookieFake, uuid.UUID) {
	sid := uuid.New()
	return &sessionCookieFake{
		now:     time.Now(),
		active:  map[string]uuid.UUID{seed: sid},
		rotated: map[string]sessionRotation{},
		revoked: map[uuid.UUID]bool{},
	}, sid
}

func (f *sessionCookieFake) Refresh(_ context.Context, in auth.RefreshInput) (*auth.AuthResult, error) {
	f.refreshCalls++
	sid, ok := f.active[in.RefreshToken]
	if !ok {
		if rot, seen := f.rotated[in.RefreshToken]; seen && f.now.Sub(rot.at) > 60*time.Second {
			f.revoked[rot.sid] = true
		}
		return nil, auth.ErrInvalidCredentials
	}
	if f.revoked[sid] {
		return nil, auth.ErrInvalidCredentials
	}
	f.next++
	fresh := fmt.Sprintf("rt-%d", f.next)
	delete(f.active, in.RefreshToken)
	f.active[fresh] = sid
	f.rotated[in.RefreshToken] = sessionRotation{sid: sid, at: f.now}
	return &auth.AuthResult{
		User:                  &ent.User{ID: uuid.New(), Email: "staff@example.com"},
		AccessToken:           fmt.Sprintf("access-%d", f.next),
		AccessTokenExpiresAt:  time.Now().Add(15 * time.Minute),
		RefreshToken:          fresh,
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		SessionID:             sid,
		Roles:                 []string{"staff"},
		Permissions:           []string{"pos.sales.create"},
	}, nil
}

func (f *sessionCookieFake) SessionIDForRefreshToken(_ context.Context, refreshToken string) (uuid.UUID, error) {
	sid, ok := f.active[refreshToken]
	if !ok || f.revoked[sid] {
		return uuid.Nil, auth.ErrInvalidCredentials
	}
	return sid, nil
}

func (f *sessionCookieFake) Logout(_ context.Context, sessionID uuid.UUID, jti string, _ time.Duration) error {
	f.revoked[sessionID] = true
	f.loggedOutJTI = jti
	return nil
}

// sessionRouter mounts the three routes the way router.go does, with a fixed allowlist.
func sessionRouter(h *AuthHandler) http.Handler {
	r := chi.NewRouter()
	r.Use(RequireSessionCSRF(func(o string) bool { return o == testAppOrigin }))
	r.Post("/session/start", h.SessionStart)
	r.Post("/session/refresh", h.SessionRefresh)
	r.Post("/session/end", h.SessionEnd)
	return r
}

type sessionReq struct {
	path   string
	xrw    string
	origin string
	cookie string
	body   string
	claims *token.Claims
	// legacyCookie is the shared pre-2026-11-18 cookie, sent under its old name.
	legacyCookie string
}

func (q sessionReq) do(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, q.path, strings.NewReader(q.body))
	if q.xrw != "" {
		req.Header.Set(SessionCSRFHeader, q.xrw)
	}
	if q.origin != "" {
		req.Header.Set("Origin", q.origin)
	}
	if q.cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieNameForOrigin(q.origin), Value: q.cookie})
	}
	if q.legacyCookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionRefreshCookie, Value: q.legacyCookie})
	}
	if q.claims != nil {
		req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), q.claims))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// okReq is a request that passes the CSRF check.
func okReq(path, cookie, body string) sessionReq {
	return sessionReq{path: path, xrw: SessionCSRFValue, origin: testAppOrigin, cookie: cookie, body: body}
}

func refreshCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	return cookieNamed(rec, cookieNameForOrigin(testAppOrigin))
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func assertSessionBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v (%s)", err, rec.Body.String())
	}
	for _, k := range []string{"access_token", "expires_in", "user", "roles", "permissions"} {
		if _, ok := body[k]; !ok {
			t.Errorf("body misses %q: %s", k, rec.Body.String())
		}
	}
	for _, k := range []string{"refresh_token", "session_id"} {
		if _, ok := body[k]; ok {
			t.Errorf("body carries %q: %s", k, rec.Body.String())
		}
	}
}

// Every refusal happens before the service is asked about a session.
func TestSessionCookieGuards(t *testing.T) {
	cases := []struct {
		name   string
		req    sessionReq
		status int
		code   string
	}{
		{"refresh without X-Requested-With", sessionReq{path: "/session/refresh", origin: testAppOrigin, cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"refresh with the XHR value", sessionReq{path: "/session/refresh", xrw: "XMLHttpRequest", origin: testAppOrigin, cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"refresh from a foreign origin", sessionReq{path: "/session/refresh", xrw: SessionCSRFValue, origin: "https://evil.example.com", cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"refresh from webmail", sessionReq{path: "/session/refresh", xrw: SessionCSRFValue, origin: "https://webmail.codevertexafrica.com", cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"refresh without Origin", sessionReq{path: "/session/refresh", xrw: SessionCSRFValue, cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"refresh from an opaque origin", sessionReq{path: "/session/refresh", xrw: SessionCSRFValue, origin: "null", cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"start from a foreign origin", sessionReq{path: "/session/start", xrw: SessionCSRFValue, origin: "https://evil.example.com", body: `{"refresh_token":"rt-0"}`}, http.StatusForbidden, "csrf_rejected"},
		{"start without X-Requested-With", sessionReq{path: "/session/start", origin: testAppOrigin, body: `{"refresh_token":"rt-0"}`}, http.StatusForbidden, "csrf_rejected"},
		{"end from a foreign origin", sessionReq{path: "/session/end", xrw: SessionCSRFValue, origin: "https://evil.example.com", cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"end without X-Requested-With", sessionReq{path: "/session/end", origin: testAppOrigin, cookie: "rt-0"}, http.StatusForbidden, "csrf_rejected"},
		{"refresh without the cookie", okReq("/session/refresh", "", ""), http.StatusUnauthorized, "no_session"},
		{"start without a token", okReq("/session/start", "", `{"refresh_token":" "}`), http.StatusBadRequest, "invalid_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, sid := newSessionCookieFake("rt-0")
			h := sessionRouter(&AuthHandler{service: svc, logger: zap.NewNop()})
			rec := c.req.do(t, h)
			if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"`+c.code+`"`) {
				t.Fatalf("%d %s, want %d %s", rec.Code, rec.Body.String(), c.status, c.code)
			}
			if svc.refreshCalls != 0 || svc.revoked[sid] {
				t.Fatalf("the session was touched: refresh calls %d, revoked %v", svc.refreshCalls, svc.revoked[sid])
			}
			if refreshCookieOf(t, rec) != nil {
				t.Fatal("a refused call set the cookie")
			}
		})
	}
}

// start moves the code-exchange token into the cookie and rotates it; refresh rotates the cookie
// again. Neither reply carries the refresh token.
func TestSessionCookieStartThenRefresh(t *testing.T) {
	svc, _ := newSessionCookieFake("rt-0")
	h := sessionRouter(&AuthHandler{service: svc, logger: zap.NewNop()})

	start := okReq("/session/start", "", `{"refresh_token":"rt-0","client_id":"pos-ui"}`).do(t, h)
	if start.Code != http.StatusOK {
		t.Fatalf("start %d %s", start.Code, start.Body.String())
	}
	assertSessionBody(t, start)
	c := refreshCookieOf(t, start)
	if c == nil || c.Value != "rt-1" {
		t.Fatalf("start cookie %+v, want rt-1", c)
	}
	if !c.HttpOnly || !c.Secure || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 {
		t.Fatalf("cookie attributes %+v", c)
	}
	if strings.Contains(start.Body.String(), "rt-1") {
		t.Fatalf("the refresh token is in the body: %s", start.Body.String())
	}

	refresh := okReq("/session/refresh", c.Value, "").do(t, h)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh %d %s", refresh.Code, refresh.Body.String())
	}
	assertSessionBody(t, refresh)
	if rc := refreshCookieOf(t, refresh); rc == nil || rc.Value != "rt-2" {
		t.Fatalf("refresh cookie %+v, want rt-2", rc)
	}

	// The token the page script saw at the code exchange no longer works.
	if again := okReq("/session/start", "", `{"refresh_token":"rt-0"}`).do(t, h); again.Code != http.StatusUnauthorized {
		t.Fatalf("reused exchange token: %d %s", again.Code, again.Body.String())
	}
}

// A replay of an old cookie value follows the service's reuse rules: inside the grace it is only
// refused (another tab's in-flight call), after it the session is revoked. A failed refresh never
// clears the cookie, which may already hold the other tab's newer token.
func TestSessionCookieReplay(t *testing.T) {
	cases := []struct {
		name        string
		after       time.Duration
		newerWorks  bool
		wantRevoked bool
	}{
		{"inside the grace", 30 * time.Second, true, false},
		{"after the grace", 61 * time.Second, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, sid := newSessionCookieFake("rt-0")
			h := sessionRouter(&AuthHandler{service: svc, logger: zap.NewNop()})
			first := okReq("/session/refresh", "rt-0", "").do(t, h)
			if first.Code != http.StatusOK {
				t.Fatalf("first refresh %d %s", first.Code, first.Body.String())
			}
			svc.now = svc.now.Add(c.after)

			replay := okReq("/session/refresh", "rt-0", "").do(t, h)
			if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), `"invalid_session"`) {
				t.Fatalf("replay %d %s", replay.Code, replay.Body.String())
			}
			if refreshCookieOf(t, replay) != nil {
				t.Fatal("a failed refresh touched the cookie")
			}
			if svc.revoked[sid] != c.wantRevoked {
				t.Fatalf("revoked %v, want %v", svc.revoked[sid], c.wantRevoked)
			}
			newer := okReq("/session/refresh", "rt-1", "").do(t, h)
			if (newer.Code == http.StatusOK) != c.newerWorks {
				t.Fatalf("newer cookie %d, want works=%v", newer.Code, c.newerWorks)
			}
		})
	}
}

// end revokes the session and clears the cookie; the cookie value stops working.
func TestSessionCookieEnd(t *testing.T) {
	cases := []struct {
		name    string
		cookie  string
		claims  bool
		wantJTI string
	}{
		{"with the cookie", "rt-0", false, ""},
		{"with the cookie and that session's access token", "rt-0", true, "jti-1"},
		{"without a cookie", "", false, ""},
		{"with a dead cookie", "rt-unknown", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, sid := newSessionCookieFake("rt-0")
			h := sessionRouter(&AuthHandler{service: svc, logger: zap.NewNop()})
			req := okReq("/session/end", c.cookie, "")
			if c.claims {
				req.claims = &token.Claims{SessionID: sid.String(), RegisteredClaims: jwt.RegisteredClaims{
					ID: "jti-1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
				}}
			}
			rec := req.do(t, h)
			if rec.Code != http.StatusOK {
				t.Fatalf("end %d %s", rec.Code, rec.Body.String())
			}
			cleared := refreshCookieOf(t, rec)
			if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 || cleared.Domain != "" || cleared.Path != "/" {
				t.Fatalf("cookie not cleared: %+v", cleared)
			}
			if c.cookie == "rt-0" && !svc.revoked[sid] {
				t.Fatal("the session was not revoked")
			}
			if svc.loggedOutJTI != c.wantJTI {
				t.Fatalf("jti %q, want %q", svc.loggedOutJTI, c.wantJTI)
			}
			if c.cookie == "rt-0" {
				if after := okReq("/session/refresh", "rt-0", "").do(t, h); after.Code != http.StatusUnauthorized {
					t.Fatalf("refresh after end %d %s", after.Code, after.Body.String())
				}
			}
		})
	}
}

// Each app gets its own refresh cookie, named from its Origin, so two apps never spend the same
// rotated token (2026-11-18).
func TestSessionCookieNamePerApp(t *testing.T) {
	cases := map[string]string{
		"https://pos.codevertexafrica.com":        "__Host-cv_refresh_pos",
		"https://books.codevertexafrica.com:443/": "__Host-cv_refresh_books",
		"https://erp.masterspace.co.ke":           "__Host-cv_refresh_erp_masterspace_co_ke",
		"":                                        "__Host-cv_refresh",
	}
	for origin, want := range cases {
		if got := cookieNameForOrigin(origin); got != want {
			t.Errorf("%q: got %q, want %q", origin, got, want)
		}
	}
	if cookieNameForOrigin("https://pos.codevertexafrica.com") == cookieNameForOrigin("https://marketflow.codevertexafrica.com") {
		t.Fatal("two apps must not share a cookie")
	}
}

// The first refresh after the change takes over the shared cookie: it rotates it into this app's
// own cookie and clears the shared one, so no other app replays the rotated value.
func TestSessionRefreshMovesTheSharedCookie(t *testing.T) {
	svc, _ := newSessionCookieFake("rt-0")
	h := sessionRouter(&AuthHandler{service: svc, logger: zap.NewNop()})
	req := okReq("/session/refresh", "", "")
	req.legacyCookie = "rt-0" // secret-scan:allow
	rec := req.do(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh with the shared cookie %d %s", rec.Code, rec.Body.String())
	}
	own := refreshCookieOf(t, rec)
	if own == nil || own.Value == "" || own.Value == "rt-0" {
		t.Fatalf("the app's own cookie holds the rotated token: %+v", own)
	}
	shared := cookieNamed(rec, SessionRefreshCookie)
	if shared == nil || shared.Value != "" || shared.MaxAge >= 0 {
		t.Fatalf("the shared cookie is cleared: %+v", shared)
	}
	// From now on the app's own cookie is used.
	if next := okReq("/session/refresh", own.Value, "").do(t, h); next.Code != http.StatusOK {
		t.Fatalf("refresh with the app's own cookie %d %s", next.Code, next.Body.String())
	}
}
