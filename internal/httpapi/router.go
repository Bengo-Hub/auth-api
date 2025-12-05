package httpapi

import (
	"net/http"
	"time"

	"github.com/bengobox/auth-service/internal/httpapi/handlers"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// RouterDeps defines router construction dependencies.
type RouterDeps struct {
	HealthHandler      http.HandlerFunc
	AuthHandlers       AuthHandlers
	RequireAuthHandler func(http.Handler) http.Handler
	RateLimitLogin     func(http.Handler) http.Handler
	RateLimitToken     func(http.Handler) http.Handler
	MetricsHandler     http.Handler
}

// AuthHandlers groups the HTTP handlers for auth routes.
type AuthHandlers struct {
	Register                 http.HandlerFunc
	Login                    http.HandlerFunc
	Refresh                  http.HandlerFunc
	RequestPasswordReset     http.HandlerFunc
	ConfirmPasswordReset     http.HandlerFunc
	Me                       http.HandlerFunc
	Logout                   http.HandlerFunc
	GoogleOAuthStart         http.HandlerFunc
	GoogleOAuthCallback      http.HandlerFunc
	GitHubOAuthStart         http.HandlerFunc
	GitHubOAuthCallback      http.HandlerFunc
	MicrosoftOAuthStart      http.HandlerFunc
	MicrosoftOAuthCallback   http.HandlerFunc
	WellKnownConfig          http.HandlerFunc
	JWKS                     http.HandlerFunc
	Authorize                http.HandlerFunc
	Token                    http.HandlerFunc
	UserInfo                 http.HandlerFunc
	MFAStartTOTP             http.HandlerFunc
	MFAConfirmTOTP           http.HandlerFunc
	MFARegenerateBackupCodes http.HandlerFunc
	MFAConsumeBackupCode     http.HandlerFunc
	AdminCreateTenant        http.HandlerFunc
	AdminListTenants         http.HandlerFunc
	AdminCreateClient        http.HandlerFunc
	AdminListClients         http.HandlerFunc
	AdminUpsertEntitlement   http.HandlerFunc
	AdminListEntitlements    http.HandlerFunc
	AdminIncrementUsage      http.HandlerFunc
	AdminRotateKeys          http.HandlerFunc
	PublicCreateTenant       http.HandlerFunc
	PublicGetTenantBySlug    http.HandlerFunc
}

// NewRouter wires HTTP routes.
func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	if deps.HealthHandler != nil {
		r.Get("/healthz", deps.HealthHandler)
	}
	if deps.MetricsHandler != nil {
		r.Method("GET", "/metrics", deps.MetricsHandler)
	}

	r.Get("/v1/docs/*", handlers.SwaggerUI)

	r.Route("/api/v1", func(r chi.Router) {
		// OIDC discovery (also serve on absolute path for issuer consistency)
		r.Group(func(r chi.Router) {
			r.Get("/.well-known/openid-configuration", deps.AuthHandlers.WellKnownConfig)
			r.Get("/.well-known/jwks.json", deps.AuthHandlers.JWKS)
			r.Get("/openapi.json", handlers.OpenAPIJSON)
			r.With(deps.RequireAuthHandler).Get("/authorize", deps.AuthHandlers.Authorize)
			r.Post("/token", deps.AuthHandlers.Token)
			r.With(deps.RequireAuthHandler).Get("/userinfo", deps.AuthHandlers.UserInfo)
		})
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", deps.AuthHandlers.Register)
			if deps.RateLimitLogin != nil {
				r.With(deps.RateLimitLogin).Post("/login", deps.AuthHandlers.Login)
			} else {
				r.Post("/login", deps.AuthHandlers.Login)
			}
			if deps.RateLimitToken != nil {
				r.With(deps.RateLimitToken).Post("/refresh", deps.AuthHandlers.Refresh)
			} else {
				r.Post("/refresh", deps.AuthHandlers.Refresh)
			}
			r.Post("/password-reset/request", deps.AuthHandlers.RequestPasswordReset)
			r.Post("/password-reset/confirm", deps.AuthHandlers.ConfirmPasswordReset)
			r.Post("/oauth/google/start", deps.AuthHandlers.GoogleOAuthStart)
			r.Get("/oauth/google/callback", deps.AuthHandlers.GoogleOAuthCallback)
			r.Post("/oauth/github/start", deps.AuthHandlers.GitHubOAuthStart)
			r.Get("/oauth/github/callback", deps.AuthHandlers.GitHubOAuthCallback)
			r.Post("/oauth/microsoft/start", deps.AuthHandlers.MicrosoftOAuthStart)
			r.Get("/oauth/microsoft/callback", deps.AuthHandlers.MicrosoftOAuthCallback)

			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Get("/me", deps.AuthHandlers.Me)
				r.Post("/logout", deps.AuthHandlers.Logout)
				r.Route("/mfa", func(r chi.Router) {
					r.Post("/totp/start", deps.AuthHandlers.MFAStartTOTP)
					r.Post("/totp/confirm", deps.AuthHandlers.MFAConfirmTOTP)
					r.Post("/backup-codes/regenerate", deps.AuthHandlers.MFARegenerateBackupCodes)
					r.Post("/backup-codes/consume", deps.AuthHandlers.MFAConsumeBackupCode)
				})
			})
		})
		// Public tenant endpoints for auto-discovery (no authentication required)
		r.Route("/tenants", func(r chi.Router) {
			r.Post("/", deps.AuthHandlers.PublicCreateTenant)
			r.Get("/by-slug/{slug}", deps.AuthHandlers.PublicGetTenantBySlug)
		})
		r.Route("/admin", func(r chi.Router) {
			if deps.RequireAuthHandler != nil {
				r.Use(deps.RequireAuthHandler)
			}
			r.Post("/tenants", deps.AuthHandlers.AdminCreateTenant)
			r.Get("/tenants", deps.AuthHandlers.AdminListTenants)
			r.Post("/clients", deps.AuthHandlers.AdminCreateClient)
			r.Get("/clients", deps.AuthHandlers.AdminListClients)
			r.Post("/entitlements", deps.AuthHandlers.AdminUpsertEntitlement)
			r.Get("/entitlements", deps.AuthHandlers.AdminListEntitlements)
			r.Post("/usage/increment", deps.AuthHandlers.AdminIncrementUsage)
			r.Post("/keys/rotate", deps.AuthHandlers.AdminRotateKeys)
		})
	})

	return r
}
