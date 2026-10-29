package httpapi

import (
	"context"
	httpware "github.com/Bengo-Hub/httpware"
	ratelimit "github.com/Bengo-Hub/shared-ratelimit"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/httpapi/handlers"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// s2sPlatformClaims wraps an admin handler for internal-key S2S use: it injects
// platform-owner claims so claims-based authorization (requireTenantAdmin) passes.
// The route is already gated by requireInternalKey (INTERNAL_SERVICE_KEY), which is
// platform-level trust, so this simply lets S2S callers reuse the JWT-admin handler.
func s2sPlatformClaims(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := &token.Claims{IsPlatformOwner: true, Scope: []string{"admin"}}
		next.ServeHTTP(w, r.WithContext(authmiddleware.ContextWithClaims(r.Context(), claims)))
	}
}

// RouterDeps defines router construction dependencies.
type RouterDeps struct {
	// TenantAppHosts are tenants' own storefront domains (config Security.TenantAppHosts); their
	// https origins are allowed by CORS so the storefront can exchange its sign-in token.
	TenantAppHosts        []string
	HealthHandler         http.HandlerFunc
	AuthHandlers          AuthHandlers
	UserHandler           *handlers.UserHandler
	LegalHandler          *handlers.LegalHandler
	ResellerHandler       *handlers.ResellerHandler
	ResellerPortalHandler *handlers.ResellerPortalHandler
	ReferralLinkHandler   *handlers.ReferralLinkHandler
	EquityPortalHandler   *handlers.EquityPortalHandler
	OutletHandler         *handlers.OutletHandler
	RBACHandler           *handlers.RBACHandler
	K8sMonitorHandler     *handlers.K8sMonitorHandler
	SealedSecretsHandler  *handlers.SealedSecretsHandler
	EquityPortalAuth      func(http.Handler) http.Handler
	RequireAuthHandler    func(http.Handler) http.Handler
	TryAuthHandler        func(http.Handler) http.Handler
	RateLimitLogin        func(http.Handler) http.Handler
	RateLimitToken        func(http.Handler) http.Handler
	// RateLimitSensitive guards unauthenticated code/account flows (email codes, password
	// reset, registration, OTP) per client IP.
	RateLimitSensitive func(http.Handler) http.Handler
	MetricsHandler     http.Handler
	// InternalServiceKey gates internal S2S endpoints (X-API-Key header).
	InternalServiceKey string
	// ValidateInternalAppKey is the dual-mode companion to InternalServiceKey: a
	// provided X-API-Key that doesn't match the static env value is also checked
	// against a live, rotatable platform App (handlers.InternalServiceKeyScope),
	// so the fleet's internal credential is manageable via Apps & Keys instead of
	// only ever being an opaque static secret. Optional — nil skips this check.
	ValidateInternalAppKey func(context.Context, string) bool
	// SwaggerHandler serves /v1/docs and /api/v1/openapi.json with app-secret-gated
	// internal/external tag filtering. Required — router construction fails without it.
	SwaggerHandler *handlers.SwaggerHandler
}

// AuthHandlers groups the HTTP handlers for auth routes.
type AuthHandlers struct {
	Register                           http.HandlerFunc
	RegisterOAuth                      http.HandlerFunc
	SendEmailCode                      http.HandlerFunc
	VerifyEmailCode                    http.HandlerFunc
	SendMyEmailCode                    http.HandlerFunc
	RequestPhoneOTP                    http.HandlerFunc
	VerifyPhoneOTP                     http.HandlerFunc
	VerifyMyEmailCode                  http.HandlerFunc
	ListMyEmails                       http.HandlerFunc
	SendAddEmailCode                   http.HandlerFunc
	VerifyAddEmailCode                 http.HandlerFunc
	SetPrimaryMyEmail                  http.HandlerFunc
	DeleteMyEmail                      http.HandlerFunc
	ListMyPhones                       http.HandlerFunc
	AddMyPhone                         http.HandlerFunc
	SetPrimaryMyPhone                  http.HandlerFunc
	DeleteMyPhone                      http.HandlerFunc
	Login                              http.HandlerFunc
	Refresh                            http.HandlerFunc
	RequestPasswordReset               http.HandlerFunc
	ConfirmPasswordReset               http.HandlerFunc
	Me                                 http.HandlerFunc
	MyMemberships                      http.HandlerFunc
	Logout                             http.HandlerFunc
	LogoutGet                          http.HandlerFunc
	GoogleOAuthStart                   http.HandlerFunc
	GoogleOAuthCallback                http.HandlerFunc
	GitHubOAuthStart                   http.HandlerFunc
	GitHubOAuthCallback                http.HandlerFunc
	MicrosoftOAuthStart                http.HandlerFunc
	SocialMFAVerify                    http.HandlerFunc
	MicrosoftOAuthCallback             http.HandlerFunc
	WellKnownConfig                    http.HandlerFunc
	JWKS                               http.HandlerFunc
	Authorize                          http.HandlerFunc
	Token                              http.HandlerFunc
	UserInfo                           http.HandlerFunc
	MFAStartTOTP                       http.HandlerFunc
	MFAConfirmTOTP                     http.HandlerFunc
	MFARegenerateBackupCodes           http.HandlerFunc
	MFAConsumeBackupCode               http.HandlerFunc
	AdminCreateTenant                  http.HandlerFunc
	AdminListTenants                   http.HandlerFunc
	AdminUpdateTenant                  http.HandlerFunc
	AdminDeleteTenant                  http.HandlerFunc
	AdminApproveTenant                 http.HandlerFunc
	AdminRejectTenant                  http.HandlerFunc
	AdminProvisionTenantOAuthRedirects http.HandlerFunc
	// Tenant backups (SSO client area): newest backup + download link, and start a new one.
	AdminGetTenantBackup         http.HandlerFunc
	AdminStartTenantBackup       http.HandlerFunc
	AdminDownloadTenantBackup    http.HandlerFunc
	AdminBackupServices          http.HandlerFunc
	AdminCreateClient            http.HandlerFunc
	AdminListClients             http.HandlerFunc
	AdminGetClient               http.HandlerFunc
	AdminUpdateClient            http.HandlerFunc
	AdminDeleteClient            http.HandlerFunc
	AdminUpsertEntitlement       http.HandlerFunc
	AdminListEntitlements        http.HandlerFunc
	AdminIncrementUsage          http.HandlerFunc
	AdminRotateKeys              http.HandlerFunc
	PublicCreateTenant           http.HandlerFunc
	PublicGetTenantBySlug        http.HandlerFunc
	PublicGetTenantLogo          http.HandlerFunc
	PublicGetTenantByID          http.HandlerFunc
	PublicListMarketplaceTenants http.HandlerFunc
	AdminCreateIntegrationConfig http.HandlerFunc
	AdminGetIntegrationConfig    http.HandlerFunc
	AdminListIntegrationConfigs  http.HandlerFunc
	S2SPlatformAlertSettings     http.HandlerFunc
	AdminDeleteIntegrationConfig http.HandlerFunc
	AdminUpdateIntegrationStatus http.HandlerFunc
	AdminRotateClientSecret      http.HandlerFunc
	// Integration requests (eTIMS + future integrations)
	CreateIntegrationRequest      http.HandlerFunc
	ListMyIntegrationRequests     http.HandlerFunc
	AdminListIntegrationRequests  http.HandlerFunc
	AdminUpdateIntegrationRequest http.HandlerFunc
	S2SNotifyIntegrationRequest   http.HandlerFunc
	// API Key management and validation
	AdminCreateAPIKey http.HandlerFunc
	AdminListAPIKeys  http.HandlerFunc
	AdminRevokeAPIKey http.HandlerFunc
	ValidateAPIKey    http.HandlerFunc // Public endpoint for service-to-service validation
	// App management (GitHub-style S2S tokens)
	AdminCreateApp      http.HandlerFunc
	AdminListApps       http.HandlerFunc
	AdminGetApp         http.HandlerFunc
	AdminUpdateApp      http.HandlerFunc
	AdminRevokeApp      http.HandlerFunc
	AdminDeleteApp      http.HandlerFunc
	AdminRotateAppToken http.HandlerFunc
	AdminSuspendApp     http.HandlerFunc
	AdminResumeApp      http.HandlerFunc
	AdminPromoteApp     http.HandlerFunc
	// Note: app token validation reuses ValidateAPIKey (detects bng_app_* prefix)
	// Session management
	ListSessions      http.HandlerFunc
	RevokeSession     http.HandlerFunc
	RevokeAllSessions http.HandlerFunc
	// Tenant member management
	AddTenantMember    http.HandlerFunc
	ListTenantMembers  http.HandlerFunc
	UpdateTenantMember http.HandlerFunc
	RemoveTenantMember http.HandlerFunc
	// S2SListTenantUsers lists a tenant's active members for S2S callers (X-API-Key).
	S2SListTenantUsers http.HandlerFunc
	// S2STenantBillingContact answers which phone a tenant's billing messages go to.
	S2STenantBillingContact http.HandlerFunc
	// S2STenantsReach pages through tenants (or one tenant's staff) with ordered contacts for
	// notifications-api broadcasts.
	S2STenantsReach http.HandlerFunc
	// S2SUserEmailVerification returns the computed email-verification state for a user.
	S2SUserEmailVerification http.HandlerFunc
	// S2SSendUserEmailCode/S2SVerifyUserEmailCode are SendMyEmailCode/VerifyMyEmailCode for a
	// downstream service that has already authenticated its own end user (including a
	// terminal/PIN JWT auth-api has no key to verify) and forwards the request S2S.
	S2SSendUserEmailCode   http.HandlerFunc
	S2SVerifyUserEmailCode http.HandlerFunc
	// S2SUserPlatformOwner tells a downstream service with its own sign-in (pos-api PIN)
	// whether the user is a platform owner.
	S2SUserPlatformOwner http.HandlerFunc
	// S2SMFAStatus/S2SMFAVerify let a service with its own separate login
	// credential (mail-ui's Stalwart mailbox password) still gate on this
	// user's auth-api TOTP MFA when the email happens to match.
	S2SMFAStatus      http.HandlerFunc
	S2SMFAVerify      http.HandlerFunc
	SetUserServicePIN http.HandlerFunc
	// Public integrations info
	ListActiveIntegrations http.HandlerFunc
	// Terms acceptance
	AcceptTerms http.HandlerFunc
	// Authenticated password change (current + new, no reset token)
	ChangePassword http.HandlerFunc
	// Use Case configuration
	GetUseCaseConfig http.HandlerFunc
	// OTP (email verification for Vera AI ticket flow)
	SendOTP   http.HandlerFunc
	VerifyOTP http.HandlerFunc
	// Platform backup management
	ListBackups    http.HandlerFunc
	DownloadBackup http.HandlerFunc
	// Outlet / branch management
	OutletHandler *handlers.OutletHandler
	// WebAuthn / passkey biometric authentication
	WebAuthnBeginRegistration    http.HandlerFunc
	WebAuthnFinishRegistration   http.HandlerFunc
	WebAuthnBeginAuthentication  http.HandlerFunc
	WebAuthnFinishAuthentication http.HandlerFunc
	WebAuthnListCredentials      http.HandlerFunc
	WebAuthnDeleteCredential     http.HandlerFunc
}

// passThrough is the no-op middleware used when a limiter is not configured (tests).
func passThrough(next http.Handler) http.Handler { return next }

// NewRouter wires HTTP routes.
func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	// Never chi's RealIP: it trusts client-sent True-Client-IP/X-Forwarded-For.
	r.Use(ratelimit.TrustedRealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(httpware.CORS(corsPolicy(deps.TenantAppHosts...)))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/docs/", http.StatusMovedPermanently)
	})

	if deps.HealthHandler != nil {
		r.Get("/healthz", deps.HealthHandler)
	}
	if deps.MetricsHandler != nil {
		r.Method("GET", "/metrics", deps.MetricsHandler)
	}

	r.Get("/v1/docs/*", deps.SwaggerHandler.SwaggerUI)

	r.Get("/.well-known/openid-configuration", deps.AuthHandlers.WellKnownConfig)
	r.Get("/.well-known/jwks.json", deps.AuthHandlers.JWKS)

	r.Route("/api/v1", func(r chi.Router) {
		// OIDC discovery (also serve on absolute path for issuer consistency)
		r.Group(func(r chi.Router) {
			r.Get("/.well-known/openid-configuration", deps.AuthHandlers.WellKnownConfig)
			r.Get("/.well-known/jwks.json", deps.AuthHandlers.JWKS)
			r.Get("/openapi.json", deps.SwaggerHandler.OpenAPIJSON)
			r.Options("/openapi.json", deps.SwaggerHandler.OpenAPIJSON)
			r.With(deps.TryAuthHandler).Get("/authorize", deps.AuthHandlers.Authorize)
			if deps.RateLimitToken != nil {
				r.With(deps.RateLimitToken).Post("/token", deps.AuthHandlers.Token)
			} else {
				r.Post("/token", deps.AuthHandlers.Token)
			}
			r.With(deps.RequireAuthHandler).Get("/userinfo", deps.AuthHandlers.UserInfo)
		})
		r.Route("/auth", func(r chi.Router) {
			r.Get("/integrations/active", deps.AuthHandlers.ListActiveIntegrations)
			r.Get("/use-case/config", deps.AuthHandlers.GetUseCaseConfig)
			sensitive := passThrough
			if deps.RateLimitSensitive != nil {
				sensitive = deps.RateLimitSensitive
			}
			r.With(sensitive).Post("/register", deps.AuthHandlers.Register)
			r.With(sensitive).Post("/register/oauth", deps.AuthHandlers.RegisterOAuth)
			// Pre-signup email verification (unauthenticated).
			r.With(sensitive).Post("/email/send-code", deps.AuthHandlers.SendEmailCode)
			r.With(sensitive).Post("/email/verify-code", deps.AuthHandlers.VerifyEmailCode)
			// Phone code sign-in for customer portals (member-only, see phone_otp_handler.go).
			if deps.AuthHandlers.RequestPhoneOTP != nil {
				r.With(sensitive).Post("/phone/otp/request", deps.AuthHandlers.RequestPhoneOTP)
				r.With(sensitive).Post("/phone/otp/verify", deps.AuthHandlers.VerifyPhoneOTP)
			}
			// Authenticated verification for EXISTING accounts (the verify-email banner /
			// dialog). Also replaces a placeholder address with the newly-proven real one.
			if deps.RequireAuthHandler != nil && deps.AuthHandlers.SendMyEmailCode != nil {
				r.With(deps.RequireAuthHandler).Post("/me/email/send-code", deps.AuthHandlers.SendMyEmailCode)
				r.With(deps.RequireAuthHandler).Post("/me/email/verify-code", deps.AuthHandlers.VerifyMyEmailCode)
			}
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
			r.With(sensitive).Post("/password-reset/request", deps.AuthHandlers.RequestPasswordReset)
			r.With(sensitive).Post("/password-reset/confirm", deps.AuthHandlers.ConfirmPasswordReset)
			r.Post("/oauth/google/start", deps.AuthHandlers.GoogleOAuthStart)
			r.Get("/oauth/google/callback", deps.AuthHandlers.GoogleOAuthCallback)
			r.Post("/oauth/github/start", deps.AuthHandlers.GitHubOAuthStart)
			r.Get("/oauth/github/callback", deps.AuthHandlers.GitHubOAuthCallback)
			r.Post("/oauth/microsoft/start", deps.AuthHandlers.MicrosoftOAuthStart)
			r.With(sensitive).Post("/oauth/mfa/verify", deps.AuthHandlers.SocialMFAVerify)
			r.Get("/oauth/microsoft/callback", deps.AuthHandlers.MicrosoftOAuthCallback)

			// GET /logout is public: for redirect-based logout (post_logout_redirect_uri from clients)
			r.Get("/logout", deps.AuthHandlers.LogoutGet)

			// WebAuthn routes: public authenticate + authenticated register/manage under one path
			if deps.AuthHandlers.WebAuthnBeginAuthentication != nil || deps.AuthHandlers.WebAuthnBeginRegistration != nil {
				r.Route("/webauthn", func(r chi.Router) {
					if deps.AuthHandlers.WebAuthnBeginAuthentication != nil {
						r.Post("/authenticate/begin", deps.AuthHandlers.WebAuthnBeginAuthentication)
						r.Post("/authenticate/finish", deps.AuthHandlers.WebAuthnFinishAuthentication)
					}
					if deps.AuthHandlers.WebAuthnBeginRegistration != nil {
						r.Group(func(r chi.Router) {
							if deps.RequireAuthHandler != nil {
								r.Use(deps.RequireAuthHandler)
							}
							r.Post("/register/begin", deps.AuthHandlers.WebAuthnBeginRegistration)
							r.Post("/register/finish", deps.AuthHandlers.WebAuthnFinishRegistration)
							r.Get("/credentials", deps.AuthHandlers.WebAuthnListCredentials)
							r.Delete("/credentials/{id}", deps.AuthHandlers.WebAuthnDeleteCredential)
						})
					}
				})
			}

			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Get("/me", deps.AuthHandlers.Me)
				// Organisation picker source (wrong-organisation SSO recovery)
				if deps.AuthHandlers.MyMemberships != nil {
					r.Get("/me/memberships", deps.AuthHandlers.MyMemberships)
				}
				// Self-service profile update (name, avatar URL, preferences)
				if deps.UserHandler != nil {
					r.Patch("/me", deps.UserHandler.UpdateMyProfile)
				}
				r.Post("/logout", deps.AuthHandlers.Logout)
				r.Route("/mfa", func(r chi.Router) {
					r.Post("/totp/start", deps.AuthHandlers.MFAStartTOTP)
					r.Post("/totp/confirm", deps.AuthHandlers.MFAConfirmTOTP)
					r.Post("/backup-codes/regenerate", deps.AuthHandlers.MFARegenerateBackupCodes)
					r.Post("/backup-codes/consume", deps.AuthHandlers.MFAConsumeBackupCode)
				})
				r.Post("/me/accept-terms", deps.AuthHandlers.AcceptTerms)
				r.Post("/me/change-password", deps.AuthHandlers.ChangePassword)
				if deps.AuthHandlers.ListMyEmails != nil {
					r.Route("/me/emails", func(r chi.Router) {
						r.Get("/", deps.AuthHandlers.ListMyEmails)
						r.Post("/send-code", deps.AuthHandlers.SendAddEmailCode)
						r.Post("/verify-code", deps.AuthHandlers.VerifyAddEmailCode)
						r.Post("/{id}/primary", deps.AuthHandlers.SetPrimaryMyEmail)
						r.Delete("/{id}", deps.AuthHandlers.DeleteMyEmail)
					})
				}
				if deps.AuthHandlers.ListMyPhones != nil {
					r.Route("/me/phones", func(r chi.Router) {
						r.Get("/", deps.AuthHandlers.ListMyPhones)
						r.Post("/", deps.AuthHandlers.AddMyPhone)
						r.Post("/{id}/primary", deps.AuthHandlers.SetPrimaryMyPhone)
						r.Delete("/{id}", deps.AuthHandlers.DeleteMyPhone)
					})
				}
				r.Route("/otp", func(r chi.Router) {
					r.With(sensitive).Post("/send", deps.AuthHandlers.SendOTP)
					r.With(sensitive).Post("/verify", deps.AuthHandlers.VerifyOTP)
				})
				r.Route("/sessions", func(r chi.Router) {
					r.Get("/", deps.AuthHandlers.ListSessions)
					r.Post("/revoke", deps.AuthHandlers.RevokeSession)
					r.Post("/revoke-all", deps.AuthHandlers.RevokeAllSessions)
				})
			})
		})
		// Public tenant endpoints for auto-discovery (no authentication required)
		r.Route("/tenants", func(r chi.Router) {
			// Creation is NOT public like the lookups below: the caller can choose
			// the tenant's own ID (for cross-service ID sync) and it creates an
			// ACTIVE tenant outright, so an unauthenticated caller could squat a
			// tenant ID before the real owner creates it, or spam the platform with
			// junk tenants. A platform-wide search found no current caller of this
			// endpoint at all (the only reference was dead code in shared-auth-client),
			// so it is now internal-service-key gated like every other genuine S2S
			// endpoint; a real future caller authenticates the same way they already
			// do for /api/v1/s2s/*.
			if deps.InternalServiceKey != "" {
				r.Group(func(r chi.Router) {
					r.Use(requireInternalKey(deps.InternalServiceKey, deps.ValidateInternalAppKey))
					r.Post("/", deps.AuthHandlers.PublicCreateTenant)
				})
			}
			r.Get("/by-slug/{slug}", deps.AuthHandlers.PublicGetTenantBySlug)
			// Tenant logo image (session payloads link here instead of inlining the image).
			if deps.AuthHandlers.PublicGetTenantLogo != nil {
				r.Get("/{slug}/logo", deps.AuthHandlers.PublicGetTenantLogo)
			}
			r.Get("/by-id/{tenant_id}", deps.AuthHandlers.PublicGetTenantByID)
			// Cross-tenant marketplace directory (public, no auth) — bulk listing of
			// active, non-demo tenants ranked by subscription tier. Same trust tier as
			// by-slug/by-id above (safe fields only, just many tenants at once).
			if deps.AuthHandlers.PublicListMarketplaceTenants != nil {
				r.Get("/marketplace", deps.AuthHandlers.PublicListMarketplaceTenants)
			}
			// Outlet management — GET is public (outlet info is not sensitive),
			// mutations require authentication.
			if deps.OutletHandler != nil {
				r.Route("/{slug}/outlets", func(r chi.Router) {
					r.Get("/", deps.OutletHandler.ListOutlets)
					r.Group(func(r chi.Router) {
						if deps.RequireAuthHandler != nil {
							r.Use(deps.RequireAuthHandler)
						}
						r.Post("/", deps.OutletHandler.CreateOutlet)
						r.Put("/{outlet_id}", deps.OutletHandler.UpdateOutlet)
						r.Delete("/{outlet_id}", deps.OutletHandler.ArchiveOutlet)
					})
				})
			}
		})
		// Outlet selection after SSO (exchange token → outlet-scoped JWT)
		if deps.OutletHandler != nil {
			r.Post("/auth/select-outlet", deps.OutletHandler.SelectOutlet)
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Get("/auth/outlets/current", deps.OutletHandler.GetCurrentOutlet)
			})
		}
		r.Route("/admin", func(r chi.Router) {
			// Public token validation — no auth required (validates token itself)
			// Handles both bng_* (api_keys) and bng_app_* (apps) via prefix detection
			r.Get("/api-keys/validate", deps.AuthHandlers.ValidateAPIKey)

			// Protected admin routes
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Post("/tenants", deps.AuthHandlers.AdminCreateTenant)
				r.Get("/tenants", deps.AuthHandlers.AdminListTenants)
				r.Route("/tenants/{tenant_id}", func(r chi.Router) {
					r.Put("/", deps.AuthHandlers.AdminUpdateTenant)
					r.Delete("/", deps.AuthHandlers.AdminDeleteTenant)
					r.Post("/approve", deps.AuthHandlers.AdminApproveTenant)
					r.Post("/reject", deps.AuthHandlers.AdminRejectTenant)
					r.Post("/provision-oauth-redirects", deps.AuthHandlers.AdminProvisionTenantOAuthRedirects)
					if deps.AuthHandlers.AdminGetTenantBackup != nil {
						r.Get("/backup", deps.AuthHandlers.AdminGetTenantBackup)
						r.Post("/backup", deps.AuthHandlers.AdminStartTenantBackup)
						r.Get("/backup/download", deps.AuthHandlers.AdminDownloadTenantBackup)
						r.Get("/backup/services", deps.AuthHandlers.AdminBackupServices)
					}
					r.Route("/members", func(r chi.Router) {
						r.Post("/", deps.AuthHandlers.AddTenantMember)
						r.Get("/", deps.AuthHandlers.ListTenantMembers)
						r.Put("/{user_id}", deps.AuthHandlers.UpdateTenantMember)
						r.Delete("/{user_id}", deps.AuthHandlers.RemoveTenantMember)
						r.Post("/{user_id}/service-pin", deps.AuthHandlers.SetUserServicePIN)
					})
				})
				r.Post("/clients", deps.AuthHandlers.AdminCreateClient)
				r.Get("/clients", deps.AuthHandlers.AdminListClients)
				r.Route("/clients/{client_id}", func(r chi.Router) {
					r.Get("/", deps.AuthHandlers.AdminGetClient)
					r.Patch("/", deps.AuthHandlers.AdminUpdateClient)
					r.Delete("/", deps.AuthHandlers.AdminDeleteClient)
					if deps.AuthHandlers.AdminRotateClientSecret != nil {
						r.Post("/rotate-secret", deps.AuthHandlers.AdminRotateClientSecret)
					}
				})
				r.Post("/entitlements", deps.AuthHandlers.AdminUpsertEntitlement)
				r.Get("/entitlements", deps.AuthHandlers.AdminListEntitlements)
				r.Post("/usage/increment", deps.AuthHandlers.AdminIncrementUsage)
				r.Post("/keys/rotate", deps.AuthHandlers.AdminRotateKeys)
				r.Post("/integrations", deps.AuthHandlers.AdminCreateIntegrationConfig)
				r.Get("/integrations/{id}", deps.AuthHandlers.AdminGetIntegrationConfig)
				r.Get("/integrations", deps.AuthHandlers.AdminListIntegrationConfigs)
				r.Put("/integrations/{id}/status", deps.AuthHandlers.AdminUpdateIntegrationStatus)
				r.Delete("/integrations/{id}", deps.AuthHandlers.AdminDeleteIntegrationConfig)
				// API Key management (requires auth)
				r.Post("/api-keys", deps.AuthHandlers.AdminCreateAPIKey)
				r.Get("/api-keys", deps.AuthHandlers.AdminListAPIKeys)
				r.Delete("/api-keys/{id}", deps.AuthHandlers.AdminRevokeAPIKey)
				// App management (GitHub-style S2S tokens)
				if deps.AuthHandlers.AdminCreateApp != nil {
					r.Post("/apps", deps.AuthHandlers.AdminCreateApp)
					r.Get("/apps", deps.AuthHandlers.AdminListApps)
					r.Route("/apps/{id}", func(r chi.Router) {
						r.Get("/", deps.AuthHandlers.AdminGetApp)
						r.Put("/", deps.AuthHandlers.AdminUpdateApp)
						r.Delete("/", deps.AuthHandlers.AdminDeleteApp)
						r.Post("/rotate", deps.AuthHandlers.AdminRotateAppToken)
						r.Post("/revoke", deps.AuthHandlers.AdminRevokeApp)
						if deps.AuthHandlers.AdminSuspendApp != nil {
							r.Post("/suspend", deps.AuthHandlers.AdminSuspendApp)
							r.Post("/resume", deps.AuthHandlers.AdminResumeApp)
						}
						if deps.AuthHandlers.AdminPromoteApp != nil {
							r.Post("/promote", deps.AuthHandlers.AdminPromoteApp)
						}
					})
				}
				// Platform database backups (platform admins only): the CronJob's pg_dumpall files.
				r.Get("/backups", deps.AuthHandlers.ListBackups)
				r.Get("/backups/{filename}", deps.AuthHandlers.DownloadBackup)
				// Platform user management (platform admins only)
				if deps.UserHandler != nil {
					r.Route("/users", func(r chi.Router) {
						r.Get("/", deps.UserHandler.AdminListUsers)
						r.Post("/", deps.UserHandler.AdminCreateUser)
						r.Route("/{user_id}", func(r chi.Router) {
							r.Get("/", deps.UserHandler.AdminGetUser)
							r.Patch("/", deps.UserHandler.AdminUpdateUser)
							r.Delete("/", deps.UserHandler.AdminDeleteUser)
							r.Post("/purge", deps.UserHandler.AdminPurgeUser)
							r.Post("/suspend", deps.UserHandler.AdminSuspendUser)
							r.Post("/deactivate", deps.UserHandler.AdminDeactivateUser)
							r.Post("/activate", deps.UserHandler.AdminActivateUser)
							r.Post("/reset-password", deps.UserHandler.AdminResetPassword)
							r.Post("/send-password-reset", deps.UserHandler.AdminSendPasswordResetEmail)
							r.Post("/mfa-enforcement", deps.UserHandler.AdminSetMfaEnforcement)
						})
					})
				}
				// Layer-1 RBAC / security management (platform admins only).
				if deps.RBACHandler != nil {
					r.Get("/permissions", deps.RBACHandler.ListPermissions)
					r.Route("/roles", func(r chi.Router) {
						r.Get("/", deps.RBACHandler.ListRoles)
						r.Post("/", deps.RBACHandler.CreateRole)
						r.Route("/{role_code}", func(r chi.Router) {
							r.Get("/", deps.RBACHandler.GetRole)
							r.Put("/", deps.RBACHandler.UpdateRole)
							r.Delete("/", deps.RBACHandler.DeleteRole)
							r.Put("/permissions", deps.RBACHandler.SetRolePermissions)
						})
					})
					r.Get("/audit-logs", deps.RBACHandler.ListAuditLogs)
					r.Get("/password-policy", deps.RBACHandler.GetPasswordPolicy)
					r.Put("/password-policy", deps.RBACHandler.UpdatePasswordPolicy)
				}
				// Platform infrastructure monitoring (platform admins only) —
				// replaces the removed Prometheus/Grafana stack.
				if deps.K8sMonitorHandler != nil {
					r.Get("/platform-monitor/overview", deps.K8sMonitorHandler.Overview)
				}
				// Sealed Secrets master-key status + rotate/backup-refresh trigger
				// (dispatches a devops-k8s GitHub Action — see sealed_secrets_handler.go).
				if deps.SealedSecretsHandler != nil {
					r.Get("/infra/sealed-secrets/status", deps.SealedSecretsHandler.Status)
					r.Post("/infra/sealed-secrets/rotate", deps.SealedSecretsHandler.Rotate)
				}
				// Integration-request review queue (eTIMS + future integrations).
				if deps.AuthHandlers.AdminListIntegrationRequests != nil {
					r.Get("/integration-requests", deps.AuthHandlers.AdminListIntegrationRequests)
					r.Patch("/integration-requests/{id}", deps.AuthHandlers.AdminUpdateIntegrationRequest)
				}
			})
		})
		// Submit an integration request (eTIMS + future integrations) — JWT optional: with a
		// tenant JWT this is the onboarded-tenant "request eTIMS integration" path; without one
		// it's an anonymous submission (the primary external-lead path is codevertex-website's
		// own Lead capture calling the S2S notify-only endpoint above instead).
		if deps.AuthHandlers.CreateIntegrationRequest != nil {
			r.With(deps.TryAuthHandler).Post("/integration-requests", deps.AuthHandlers.CreateIntegrationRequest)
		}
		// The caller's own integration/access requests (e.g. developer docs-access gating) —
		// requires a real session, unlike the create route above, since "mine" needs a known caller.
		if deps.RequireAuthHandler != nil && deps.AuthHandlers.ListMyIntegrationRequests != nil {
			r.With(deps.RequireAuthHandler).Get("/integration-requests/mine", deps.AuthHandlers.ListMyIntegrationRequests)
		}
		// Note: a prior redundant "/developer/clients" GET/POST-only route (backed by
		// developer_handler.go) was removed 2026-08-18 — it duplicated AdminCreateClient/
		// AdminListClients above with no update/delete/rotate at all, and the frontend's
		// delete button called a route that was never registered. The admin client CRUD
		// above (now with secret generation + rotation) is the one consolidated path.

		// Legal documents (public read, admin write). NOTE: RequireAuthHandler only
		// proves the caller is *someone*; the /admin/* routes below additionally
		// enforce platform-admin inside the handler (isPlatformOrS2SAdmin), since
		// chi has no admin-only middleware group in this service.
		if deps.LegalHandler != nil {
			r.Get("/legal/documents/{type}", deps.LegalHandler.GetCurrentDocument)
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Post("/auth/legal/accept", deps.LegalHandler.AcceptDocument)
				r.Post("/auth/legal/sign", deps.LegalHandler.SignDocument)
				r.Post("/auth/equity/apply", deps.LegalHandler.CreateApplication)
			})
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Post("/admin/legal/documents", deps.LegalHandler.UpsertDocument)
				r.Get("/admin/equity/applications", deps.LegalHandler.ListApplications)
				r.Put("/admin/equity/applications/{id}", deps.LegalHandler.UpdateApplication)
			})
		}

		// Certified Reseller & Partner Program applications — mirrors the equity
		// application flow's auth/permission gating exactly (see legal_handler.go above),
		// substituting reseller for equity. Self-serve apply's JWT is optional, same
		// idiom as /integration-requests above: with a tenant JWT this is an existing
		// tenant applying to also become a reseller; without one it's a prospective
		// partner with no Codevertex tenant yet.
		if deps.ResellerHandler != nil {
			r.With(deps.TryAuthHandler).Post("/auth/reseller/apply", deps.ResellerHandler.CreateApplication)
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Get("/admin/reseller/applications", deps.ResellerHandler.ListApplications)
				r.Get("/admin/reseller/applications/{id}", deps.ResellerHandler.GetApplication)
				r.Put("/admin/reseller/applications/{id}", deps.ResellerHandler.UpdateApplication)
			})
		}

		// Reseller self-service portal (read-only, any authenticated member of a certified
		// reseller tenant — is_reseller checked inside the handler, not a separate admin gate).
		// See ResellerPortalHandler's own doc comment / plan register item G9.
		if deps.ResellerPortalHandler != nil {
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Get("/reseller/me", deps.ResellerPortalHandler.GetOwnStatus)
				r.Get("/reseller/clients", deps.ResellerPortalHandler.GetOwnClients)
			})
		}

		// Referral links
		if deps.ReferralLinkHandler != nil {
			r.Get("/referrals/link/{code}", deps.ReferralLinkHandler.GetLinkByCode)
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Post("/admin/referral-links", deps.ReferralLinkHandler.CreateReferralLink)
				r.Get("/admin/referral-links", deps.ReferralLinkHandler.ListReferralLinks)
			})
		}

		// Equity portal JWT issuance (platform-admin only, enforced in the handler)
		// + portal data endpoint. The minted portal token carries scope
		// token.ScopeEquityPortal, which RequireAuth rejects everywhere else, so it
		// can only ever reach the EquityPortalAuth group below.
		if deps.EquityPortalHandler != nil {
			r.Group(func(r chi.Router) {
				if deps.RequireAuthHandler != nil {
					r.Use(deps.RequireAuthHandler)
				}
				r.Post("/admin/equity-holders/{treasury_holder_id}/portal-link", deps.EquityPortalHandler.GeneratePortalLink)
			})
			if deps.EquityPortalAuth != nil {
				r.Group(func(r chi.Router) {
					r.Use(deps.EquityPortalAuth)
					r.Get("/equity-portal/me", deps.EquityPortalHandler.Me)
				})
			}
		}
	})

	// Internal S2S endpoints — secured by INTERNAL_SERVICE_KEY (X-API-Key header).
	// Not exposed via CORS; cluster-internal callers only.
	if deps.InternalServiceKey != "" {
		r.Group(func(r chi.Router) {
			r.Use(requireInternalKey(deps.InternalServiceKey, deps.ValidateInternalAppKey))
			if deps.OutletHandler != nil {
				r.Post("/internal/outlets/republish", deps.OutletHandler.RepublishOutletEvents)
			}
			// S2S tenant user listing (erp-api employee backfill).
			if deps.AuthHandlers.S2SListTenantUsers != nil {
				r.Get("/api/v1/s2s/{tenant}/users", deps.AuthHandlers.S2SListTenantUsers)
			}
			// S2S billing phone (tenant admin, else main outlet, else tenant): notifications-api
			// sends subscription invoices and payment reminders there over WhatsApp.
			if deps.AuthHandlers.S2STenantBillingContact != nil {
				r.Get("/api/v1/s2s/{tenant}/billing-contact", deps.AuthHandlers.S2STenantBillingContact)
			}
			// S2S broadcast reach (owners and admins with verified contacts first, then the tenant's
			// contacts, then the head office outlet's), paged: notifications-api's bulk messages.
			// Registered before /{tenant}/... routes would not matter: the literal "tenants" segment
			// sits on its own path.
			if deps.AuthHandlers.S2STenantsReach != nil {
				r.Get("/api/v1/s2s/tenants/reach", deps.AuthHandlers.S2STenantsReach)
			}
			// S2S email-verification state — downstream /auth/me forwards this so every app
			// shows the same graduated verify banner.
			if deps.AuthHandlers.S2SUserEmailVerification != nil {
				r.Get("/api/v1/s2s/users/{user_id}/email-verification", deps.AuthHandlers.S2SUserEmailVerification)
			}
			// S2S send/verify — lets a downstream service's own terminal/PIN session (which
			// auth-api cannot itself validate) drive the SAME embedded OTP dialog as SSO.
			if deps.AuthHandlers.S2SSendUserEmailCode != nil {
				r.Post("/api/v1/s2s/users/{user_id}/email/send-code", deps.AuthHandlers.S2SSendUserEmailCode)
			}
			if deps.AuthHandlers.S2SVerifyUserEmailCode != nil {
				r.Post("/api/v1/s2s/users/{user_id}/email/verify-code", deps.AuthHandlers.S2SVerifyUserEmailCode)
			}
			if deps.AuthHandlers.S2SUserPlatformOwner != nil {
				r.Get("/api/v1/s2s/users/{user_id}/platform-owner", deps.AuthHandlers.S2SUserPlatformOwner)
			}
			// S2S MFA federation (mail-ui webmail login) - see comments on the
			// Deps fields above and on the handlers themselves.
			if deps.AuthHandlers.S2SMFAStatus != nil {
				r.Get("/api/v1/s2s/mfa/status", deps.AuthHandlers.S2SMFAStatus)
			}
			if deps.AuthHandlers.S2SMFAVerify != nil {
				r.Post("/api/v1/s2s/mfa/verify", deps.AuthHandlers.S2SMFAVerify)
			}
			// S2S member provisioning: owning services (pos-api, etc.) create/link a
			// user by email and get the REAL auth user id back, so no service ever
			// mints its own orphan user id. Reuses the JWT-admin AddTenantMember via
			// injected platform claims; {tenant_id} must be the tenant UUID.
			if deps.AuthHandlers.AddTenantMember != nil {
				r.Post("/api/v1/s2s/tenants/{tenant_id}/members", s2sPlatformClaims(deps.AuthHandlers.AddTenantMember))
			}
			// S2S portal password reissue: lets an owning service resend the credentials of a
			// student or parent account the person has not yet taken over. The handler refuses
			// staff and claimed accounts, so a service key cannot reach anyone else.
			if deps.UserHandler != nil {
				r.Post("/api/v1/s2s/tenants/{tenant_id}/members/{user_id}/portal-password", deps.UserHandler.S2SPortalPasswordReset)
			}
			// S2S tenant backups (platform operations from inside the cluster): same handlers as the
			// tenant-admin routes, with injected platform claims.
			if deps.AuthHandlers.AdminGetTenantBackup != nil {
				r.Get("/api/v1/s2s/tenants/{tenant_id}/backup", s2sPlatformClaims(deps.AuthHandlers.AdminGetTenantBackup))
				r.Post("/api/v1/s2s/tenants/{tenant_id}/backup", s2sPlatformClaims(deps.AuthHandlers.AdminStartTenantBackup))
				r.Get("/api/v1/s2s/tenants/{tenant_id}/backup/download", s2sPlatformClaims(deps.AuthHandlers.AdminDownloadTenantBackup))
				r.Get("/api/v1/s2s/tenants/{tenant_id}/backup/services", s2sPlatformClaims(deps.AuthHandlers.AdminBackupServices))
			}
			// S2S service-role registry: owning services push their role catalogue
			// here; idempotent upsert by role_code (no duplicate roles).
			if deps.RBACHandler != nil {
				r.Post("/api/v1/s2s/roles/sync", deps.RBACHandler.SyncServiceRoles)
			}
			// fleet-health-watcher's configured alert channels (Slack webhook /
			// alert email) — admin-configured via the existing generic
			// integrations CRUD (POST /admin/integrations, name
			// "platform_alert_channels"). See admin_handler.go for the
			// fallback-friendly contract (always 200, empty object if unset).
			if deps.AuthHandlers.S2SPlatformAlertSettings != nil {
				r.Get("/api/v1/s2s/platform-alert-settings", deps.AuthHandlers.S2SPlatformAlertSettings)
			}
			// codevertex-website (and any other trusted S2S caller) triggers the eTIMS/
			// integration-request Slack+email notification without creating an
			// IntegrationRequest row itself — the caller keeps owning its own lead record.
			if deps.AuthHandlers.S2SNotifyIntegrationRequest != nil {
				r.Post("/api/v1/s2s/notifications/etims-integration-request", deps.AuthHandlers.S2SNotifyIntegrationRequest)
			}
		})
	}

	// Short-link redirect — public, outside /api/v1 prefix.
	// GET /p/{code}  →  302  →  /equity-holder/?token=<JWT>  (on auth-ui)
	if deps.EquityPortalHandler != nil {
		r.Get("/p/{code}", deps.EquityPortalHandler.RedeemShortLink)
	}

	return r
}

// corsOrigins are the browser origins allowed to call the auth API. The two wildcard entries cover
// every https subdomain of the platform domain and of masterspace.co.ke (the primary tenant's
// custom domain, where the ERP UI exchanges its OIDC token cross-origin). Keep the hosts in sync
// with cmd/seed buildRedirects().
var corsOrigins = []string{
	"http://localhost:3000", "http://localhost:3001", "http://localhost:3010", "http://localhost:4101",
	"http://127.0.0.1:3000", "http://127.0.0.1:3001", "http://127.0.0.1:3010",
	"https://localhost:3000", "https://auth.codevertex.local:4101",
	"https://codevertexafrica.com", "https://theurbanloftcafe.com",
	"https://*.codevertexafrica.com", "https://*.masterspace.co.ke",
}

// corsPolicy is the fleet's standard CORS policy plus the WebAuthn session header the passkey
// ceremony sends and reads back. tenantHosts adds each tenant storefront domain as an https origin.
func corsPolicy(tenantHosts ...string) httpware.CORSConfig {
	origins := append([]string{}, corsOrigins...)
	for _, h := range tenantHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			origins = append(origins, "https://"+h)
		}
	}
	cfg := httpware.StandardCORS(origins, "X-WebAuthn-Session")
	cfg.ExposedHeaders = append(cfg.ExposedHeaders, "X-WebAuthn-Session")
	return cfg
}

// requireInternalKey returns middleware that validates the X-API-Key header
// against the static env-configured key OR, when provided, a live rotatable
// platform App carrying handlers.InternalServiceKeyScope (see ValidateInternalAppKey).
func requireInternalKey(key string, validateApp func(context.Context, string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if httpware.ValidServiceKey(r, key) {
				next.ServeHTTP(w, r)
				return
			}
			if validateApp != nil && validateApp(r.Context(), r.Header.Get(httpware.HeaderAPIKey)) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		})
	}
}
