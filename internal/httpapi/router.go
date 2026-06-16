package httpapi

import (
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/httpapi/handlers"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// RouterDeps defines router construction dependencies.
type RouterDeps struct {
	HealthHandler        http.HandlerFunc
	AuthHandlers         AuthHandlers
	UserHandler          *handlers.UserHandler
	LegalHandler         *handlers.LegalHandler
	ReferralLinkHandler  *handlers.ReferralLinkHandler
	EquityPortalHandler  *handlers.EquityPortalHandler
	OutletHandler        *handlers.OutletHandler
	RBACHandler          *handlers.RBACHandler
	EquityPortalAuth     func(http.Handler) http.Handler
	RequireAuthHandler   func(http.Handler) http.Handler
	TryAuthHandler       func(http.Handler) http.Handler
	RateLimitLogin       func(http.Handler) http.Handler
	RateLimitToken       func(http.Handler) http.Handler
	MetricsHandler       http.Handler
	// InternalServiceKey gates internal S2S endpoints (X-API-Key header).
	InternalServiceKey string
}

// AuthHandlers groups the HTTP handlers for auth routes.
type AuthHandlers struct {
	Register                     http.HandlerFunc
	RegisterOAuth                http.HandlerFunc
	Login                        http.HandlerFunc
	Refresh                      http.HandlerFunc
	RequestPasswordReset         http.HandlerFunc
	ConfirmPasswordReset         http.HandlerFunc
	Me                           http.HandlerFunc
	Logout                       http.HandlerFunc
	LogoutGet                    http.HandlerFunc
	GoogleOAuthStart             http.HandlerFunc
	GoogleOAuthCallback          http.HandlerFunc
	GitHubOAuthStart             http.HandlerFunc
	GitHubOAuthCallback          http.HandlerFunc
	MicrosoftOAuthStart          http.HandlerFunc
	MicrosoftOAuthCallback       http.HandlerFunc
	WellKnownConfig              http.HandlerFunc
	JWKS                         http.HandlerFunc
	Authorize                    http.HandlerFunc
	Token                        http.HandlerFunc
	UserInfo                     http.HandlerFunc
	MFAStartTOTP                 http.HandlerFunc
	MFAConfirmTOTP               http.HandlerFunc
	MFARegenerateBackupCodes     http.HandlerFunc
	MFAConsumeBackupCode         http.HandlerFunc
	AdminCreateTenant            http.HandlerFunc
	AdminListTenants             http.HandlerFunc
	AdminUpdateTenant                  http.HandlerFunc
	AdminDeleteTenant                  http.HandlerFunc
	AdminProvisionTenantOAuthRedirects http.HandlerFunc
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
	AdminCreateIntegrationConfig http.HandlerFunc
	AdminGetIntegrationConfig    http.HandlerFunc
	AdminListIntegrationConfigs  http.HandlerFunc
	AdminDeleteIntegrationConfig http.HandlerFunc
	AdminUpdateIntegrationStatus http.HandlerFunc
	DeveloperListClients         http.HandlerFunc
	DeveloperCreateClient        http.HandlerFunc
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
	SetUserServicePIN  http.HandlerFunc
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
	ListBackups          http.HandlerFunc
	DownloadBackup       http.HandlerFunc
	GetBackupSettings    http.HandlerFunc
	UpdateBackupSettings http.HandlerFunc
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

// NewRouter wires HTTP routes.
func NewRouter(deps RouterDeps) http.Handler {
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second))
	r.Use(cors.Handler(cors.Options{
		// AllowOriginFunc allows dynamic origin checking for credentials mode
		// This returns true for allowed origins, enabling credentials with specific origins
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			// Allow empty origin (same-origin requests)
			if origin == "" {
				return true
			}
			// Allow all localhost origins for development
			if origin == "http://localhost:3000" ||
				origin == "http://localhost:3001" ||
				origin == "http://localhost:4101" ||
				origin == "http://127.0.0.1:3000" ||
				origin == "http://127.0.0.1:3001" ||
				origin == "https://localhost:3000" ||
				origin == "https://auth.codevertex.local:4101" {
				return true
			}
			// Allow production origins (explicit list; from shared-docs/sso-integration-guide.md and cmd/seed)
			if origin == "https://accounts.codevertexitsolutions.com" ||
				origin == "https://sso.codevertexitsolutions.com" ||
				origin == "https://codevertexitsolutions.com" ||
				origin == "https://ordersapp.codevertexitsolutions.com" ||
				origin == "https://theurbanloftcafe.com" ||
				origin == "https://notifications.codevertexitsolutions.com" ||
				origin == "https://books.codevertexitsolutions.com" ||
				origin == "https://pricing.codevertexitsolutions.com" ||
				origin == "https://pos.codevertexitsolutions.com" ||
				origin == "https://inventory.codevertexitsolutions.com" ||
				origin == "https://logistics.codevertexitsolutions.com" ||
				origin == "https://riderapp.codevertexitsolutions.com" ||
				origin == "https://erp.codevertexitsolutions.com" {
				return true
			}
			// Allow any subdomain of codevertexitsolutions.com OR masterspace.co.ke
			// (https only). masterspace.co.ke is the primary tenant's custom domain:
			// the ERP UI is served at https://erp.masterspace.co.ke and must be able
			// to POST the OIDC token exchange to this auth-service cross-origin
			// (otherwise the browser blocks it with "Failed to fetch" / no CORS
			// header). erp.codevertexitsolutions.com is already covered by the first
			// suffix. Keep this in sync with cmd/seed buildRedirects() hosts.
			const httpsPrefix = "https://"
			for _, suffix := range []string{".codevertexitsolutions.com", ".masterspace.co.ke"} {
				if len(origin) > len(httpsPrefix)+len(suffix) &&
					origin[:len(httpsPrefix)] == httpsPrefix &&
					origin[len(origin)-len(suffix):] == suffix {
					return true
				}
			}
			return false
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "X-Requested-With", "X-API-Key", "X-Tenant-Slug", "X-Tenant-ID", "X-WebAuthn-Session"},
		ExposedHeaders:   []string{"Set-Cookie", "X-WebAuthn-Session"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/docs/", http.StatusMovedPermanently)
	})

	if deps.HealthHandler != nil {
		r.Get("/healthz", deps.HealthHandler)
	}
	if deps.MetricsHandler != nil {
		r.Method("GET", "/metrics", deps.MetricsHandler)
	}

	r.Get("/v1/docs/*", handlers.SwaggerUI)

	r.Get("/.well-known/openid-configuration", deps.AuthHandlers.WellKnownConfig)
	r.Get("/.well-known/jwks.json", deps.AuthHandlers.JWKS)

	r.Route("/api/v1", func(r chi.Router) {
		// OIDC discovery (also serve on absolute path for issuer consistency)
		r.Group(func(r chi.Router) {
			r.Get("/.well-known/openid-configuration", deps.AuthHandlers.WellKnownConfig)
			r.Get("/.well-known/jwks.json", deps.AuthHandlers.JWKS)
			r.Get("/openapi.json", handlers.OpenAPIJSON)
			r.With(deps.TryAuthHandler).Get("/authorize", deps.AuthHandlers.Authorize)
			r.Post("/token", deps.AuthHandlers.Token)
			r.With(deps.RequireAuthHandler).Get("/userinfo", deps.AuthHandlers.UserInfo)
		})
		r.Route("/auth", func(r chi.Router) {
			r.Get("/integrations/active", deps.AuthHandlers.ListActiveIntegrations)
			r.Get("/use-case/config", deps.AuthHandlers.GetUseCaseConfig)
			r.Post("/register", deps.AuthHandlers.Register)
			r.Post("/register/oauth", deps.AuthHandlers.RegisterOAuth)
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
				r.Route("/otp", func(r chi.Router) {
					r.Post("/send", deps.AuthHandlers.SendOTP)
					r.Post("/verify", deps.AuthHandlers.VerifyOTP)
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
			r.Post("/", deps.AuthHandlers.PublicCreateTenant)
			r.Get("/by-slug/{slug}", deps.AuthHandlers.PublicGetTenantBySlug)
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
					r.Post("/provision-oauth-redirects", deps.AuthHandlers.AdminProvisionTenantOAuthRedirects)
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
					})
				}
				// Platform backup management (platform admins only)
				r.Get("/backups", deps.AuthHandlers.ListBackups)
				// Auto-backup activation settings — register the static path BEFORE the
				// {filename} wildcard so GET /backups/settings is never shadowed.
				r.Get("/backups/settings", deps.AuthHandlers.GetBackupSettings)
				r.Put("/backups/settings", deps.AuthHandlers.UpdateBackupSettings)
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
			})
		})
		r.Route("/developer", func(r chi.Router) {
			if deps.RequireAuthHandler != nil {
				r.Use(deps.RequireAuthHandler)
			}
			r.Get("/clients", deps.AuthHandlers.DeveloperListClients)
			r.Post("/clients", deps.AuthHandlers.DeveloperCreateClient)
		})

		// Legal documents (public read, admin write)
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

		// Equity portal JWT issuance (admin authed) + portal data endpoint
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
			r.Use(requireInternalKey(deps.InternalServiceKey))
			if deps.OutletHandler != nil {
				r.Post("/internal/outlets/republish", deps.OutletHandler.RepublishOutletEvents)
			}
			// S2S tenant user listing (erp-api employee backfill).
			if deps.AuthHandlers.S2SListTenantUsers != nil {
				r.Get("/api/v1/s2s/{tenant}/users", deps.AuthHandlers.S2SListTenantUsers)
			}
			// S2S service-role registry: owning services push their role catalogue
			// here; idempotent upsert by role_code (no duplicate roles).
			if deps.RBACHandler != nil {
				r.Post("/api/v1/s2s/roles/sync", deps.RBACHandler.SyncServiceRoles)
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

// requireInternalKey returns middleware that validates the X-API-Key header.
func requireInternalKey(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-API-Key") != key {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
