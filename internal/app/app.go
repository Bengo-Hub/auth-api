package app

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/cache"
	subscriptionclient "github.com/bengobox/auth-api/internal/clients/subscription"
	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/httpapi"
	"github.com/bengobox/auth-api/internal/httpapi/handlers"
	httpmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/modules/platformbackup"
	eventslib "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/password"
	platformevents "github.com/bengobox/auth-api/internal/platform/events"
	githubprovider "github.com/bengobox/auth-api/internal/providers/github"
	googleprovider "github.com/bengobox/auth-api/internal/providers/google"
	microsoftprovider "github.com/bengobox/auth-api/internal/providers/microsoft"
	"github.com/bengobox/auth-api/internal/revocation"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/services/integrations"
	"github.com/bengobox/auth-api/internal/services/mfa"
	"github.com/bengobox/auth-api/internal/services/usecase"
	"github.com/bengobox/auth-api/internal/services/oidc"
	webauthnSvc "github.com/bengobox/auth-api/internal/services/webauthn"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// App wires core dependencies and exposes server lifecycle controls.
type App struct {
	cfg                      *config.Config
	logger                   *zap.Logger
	entClient                *ent.Client
	db                       *sql.DB
	redis                    *redis.Client
	natsConn                 *nats.Conn
	outboxPublisher          *eventslib.OutboxPoller
	subscriptionSubscriber   *platformevents.SubscriptionSubscriber
	httpServer               *http.Server
}

// New constructs the application.
func New(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*App, error) {
	entClient, sqlDB, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}
	if cfg.Database.RunMigrations {
		if err := database.RunMigrations(ctx, entClient); err != nil {
			return nil, err
		}
	}

	redisClient, err := cache.New(cfg.Redis)
	if err != nil {
		return nil, err
	}

	integrationSvc := integrations.New(entClient, redisClient, cfg.Security.EncryptionKey, cfg.Token.Issuer)
	if err := integrationSvc.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialize integrations library: %w", err)
	}

	tokenSvc, err := token.NewService(cfg.Token)
	if err != nil {
		return nil, err
	}

	googleProvider, err := googleprovider.New(integrationSvc)
	if err != nil {
		return nil, err
	}
	githubProvider, err := githubprovider.New(integrationSvc)
	if err != nil {
		return nil, err
	}
	microsoftProvider, err := microsoftprovider.New(integrationSvc)
	if err != nil {
		return nil, err
	}

	hasher := password.NewHasher(cfg.Security)
	auditor := audit.New(entClient, logger)

	// Initialize subscription client for JWT enrichment (optional).
	// The API key is resolved dynamically from integration_configs (DB, cached 5 min)
	// so superusers can rotate it via auth-ui without restarting the pod.
	// Falls back to AUTH_SUBSCRIPTION_API_KEY env var if not found in DB.
	var subClient *subscriptionclient.Client
	if cfg.Subscription.Enabled && cfg.Subscription.BaseURL != "" {
		keyProvider := subscriptionclient.KeyProviderFunc(func(ctx context.Context) string {
			creds, err := integrationSvc.GetDecryptedConfig(ctx, nil, "subscription_api_key")
			if err != nil {
				// Not yet in DB, decryption failed (seeder stores plain JSON until
				// superuser saves via auth-ui which re-encrypts), or other error.
				// Fall through to env var fallback.
				return ""
			}
			return creds["key"]
		})
		// Warm the cache on startup: if the key isn't in DB yet (seeder not run),
		// we'll fall back to env var — logged below at first use, not here.
		subClient = subscriptionclient.NewClient(subscriptionclient.Config{
			BaseURL:     cfg.Subscription.BaseURL,
			APIKey:      cfg.Subscription.APIKey, // static fallback from env
			KeyProvider: keyProvider,
			Timeout:     cfg.Subscription.Timeout,
		}, logger)
		logger.Info("subscription client initialized",
			zap.String("base_url", cfg.Subscription.BaseURL),
			zap.Bool("dynamic_key", true),
		)
	}

	// Initialize NATS event publishing (optional)
	var natsConn *nats.Conn
	var outboxPub *eventslib.OutboxPoller
	if cfg.Events.Enabled {
		natsConn, err = platformevents.Connect(cfg.Events)
		if err != nil {
			return nil, fmt.Errorf("connect to NATS: %w", err)
		}
		logger.Info("NATS connection established",
			zap.String("url", cfg.Events.NATSURL),
		)

		outboxRepo := eventslib.NewSQLOutboxRepository(sqlDB)
		outboxNatsPublisher := eventslib.NewNATSAdapter(natsConn, logger)
		outboxPub = eventslib.NewOutboxPoller(outboxRepo, outboxNatsPublisher, logger, eventslib.PollerConfig{
			BatchSize:  cfg.Events.OutboxBatchSize,
			PollPeriod: cfg.Events.OutboxPollPeriod,
		})
		outboxPub.Start(ctx)
	}

	authService := auth.New(auth.Dependencies{
		EntClient:          entClient,
		TokenSvc:           tokenSvc,
		Hasher:             hasher,
		Config:             cfg,
		Auditor:            auditor,
		Logger:             logger,
		Google:             googleProvider,
		Revoker:            revocation.New(redisClient, cfg.Redis.Namespace),
		GitHub:             githubProvider,
		Microsoft:          microsoftProvider,
		SubscriptionClient: subClient,
		Integrations:       integrationSvc,
	})

	usecaseSvc := usecase.NewService()
	authHandler := handlers.NewAuthHandler(authService, integrationSvc, usecaseSvc, logger, redisClient, cfg.Redis.Namespace, cfg.Security.CookieDomain, cfg.Security.LogoutRedirectHosts)
	revocationStore := revocation.New(redisClient, cfg.Redis.Namespace)
	authMiddleware := httpmiddleware.NewAuth(authService, revocationStore)
	// Enable session cookie resolution: bb_session cookies now contain a session
	// UUID instead of the full JWT (admin tokens exceed browser 4KB cookie limit).
	authMiddleware.SetSessionResolver(httpmiddleware.NewRedisSessionResolver(redisClient, cfg.Redis.Namespace))
	rateLimiter := httpmiddleware.NewRateLimiter(redisClient, cfg.Redis.Namespace)
	oidcService := oidc.New(entClient, tokenSvc, cfg)
	oidcHandler := handlers.NewOIDCHandlerWithRolesPermissions(cfg, oidcService, authMiddleware, tokenSvc, authService, logger)
	mfaService := mfa.New(entClient, cfg.Token.Issuer)
	mfaHandler := handlers.NewMFAHandler(mfaService, logger)

	webAuthnService, webAuthnErr := webauthnSvc.New(webauthnSvc.Config{
		RPID:          cfg.WebAuthn.RPID,
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	}, entClient, redisClient, cfg.Redis.Namespace, logger)
	if webAuthnErr != nil {
		logger.Warn("webauthn disabled: failed to init", zap.Error(webAuthnErr))
	}
	var webAuthnHandler *handlers.WebAuthnHandler
	if webAuthnService != nil {
		webAuthnHandler = handlers.NewWebAuthnHandler(webAuthnService, authService, logger, redisClient, cfg.Redis.Namespace)
	}

	adminHandler := handlers.NewAdminHandler(entClient, tokenSvc, integrationSvc, subClient, hasher, cfg.App.AuthUIURL, logger)
	// Platform-wide auto-backup activation (single-row, opt-in, default OFF).
	platformBackupSvc := platformbackup.NewService(entClient)
	backupHandler := handlers.NewBackupHandler(cfg.Backup.ServiceURL, cfg.Backup.Enabled, platformBackupSvc)
	outletHandler := handlers.NewOutletHandler(entClient, tokenSvc, logger)
	developerHandler := handlers.NewDeveloperHandler(entClient, logger)
	apiKeyHandler := handlers.NewAPIKeyHandler(entClient, logger)
	appHandler := handlers.NewAppHandler(entClient, logger)
	userHandler := handlers.NewUserHandler(entClient, hasher, authService, redisClient, cfg.Redis.Namespace, cfg.App.AuthUIURL, logger)
	legalHandler := handlers.NewLegalHandler(entClient, logger)
	referralLinkHandler := handlers.NewReferralLinkHandler(entClient, logger)
	equityPortalHandler := handlers.NewEquityPortalHandler(entClient, tokenSvc, cfg.Token.Issuer, cfg.App.AuthUIURL, logger)
	rbacHandler := handlers.NewRBACHandler(authService, logger)

	router := httpapi.NewRouter(httpapi.RouterDeps{
		OutletHandler:      outletHandler,
		InternalServiceKey: cfg.Subscription.APIKey,
		HealthHandler:       handlers.Health,
		MetricsHandler:      promhttp.Handler(),
		UserHandler:         userHandler,
		LegalHandler:        legalHandler,
		ReferralLinkHandler: referralLinkHandler,
		EquityPortalHandler: equityPortalHandler,
		RBACHandler:         rbacHandler,
		EquityPortalAuth:    handlers.EquityPortalAuth(tokenSvc),
		AuthHandlers: httpapi.AuthHandlers{
			Register:                     authHandler.Register,
			RegisterOAuth:                authHandler.RegisterOAuth,
			SendEmailCode:                authHandler.SendEmailCode,
			VerifyEmailCode:              authHandler.VerifyEmailCode,
			Login:                        authHandler.Login,
			Refresh:                      authHandler.Refresh,
			RequestPasswordReset:         authHandler.RequestPasswordReset,
			ConfirmPasswordReset:         authHandler.ConfirmPasswordReset,
			Me:                           authHandler.Me,
			Logout:                       authHandler.Logout,
			LogoutGet:                    authHandler.LogoutGet,
			GoogleOAuthStart:             authHandler.GoogleOAuthStart,
			GoogleOAuthCallback:          authHandler.GoogleOAuthCallback,
			GitHubOAuthStart:             authHandler.GitHubOAuthStart,
			GitHubOAuthCallback:          authHandler.GitHubOAuthCallback,
			MicrosoftOAuthStart:          authHandler.MicrosoftOAuthStart,
			MicrosoftOAuthCallback:       authHandler.MicrosoftOAuthCallback,
			WellKnownConfig:              oidcHandler.WellKnownConfig,
			JWKS:                         oidcHandler.JWKS,
			Authorize:                    oidcHandler.Authorize,
			Token:                        oidcHandler.Token,
			UserInfo:                     oidcHandler.UserInfo,
			MFAStartTOTP:                 mfaHandler.StartTOTP,
			MFAConfirmTOTP:               mfaHandler.ConfirmTOTP,
			MFARegenerateBackupCodes:     mfaHandler.RegenerateBackupCodes,
			MFAConsumeBackupCode:         mfaHandler.ConsumeBackupCode,
			AcceptTerms:                  authHandler.AcceptTerms,
			ChangePassword:               authHandler.ChangePassword,
			ListSessions:                 authHandler.ListSessions,
			RevokeSession:                authHandler.RevokeSession,
			RevokeAllSessions:            authHandler.RevokeAllSessions,
			ListActiveIntegrations:       authHandler.ListActiveIntegrations,
			AdminUpsertEntitlement:       adminHandler.UpsertEntitlement,
			AdminListEntitlements:        adminHandler.ListEntitlements,
			AdminIncrementUsage:          adminHandler.IncrementUsage,
			AdminCreateTenant:            adminHandler.CreateTenant,
			AdminListTenants:             adminHandler.ListTenants,
			AdminUpdateTenant:                  adminHandler.UpdateTenant,
			AdminDeleteTenant:                  adminHandler.DeleteTenant,
			AdminProvisionTenantOAuthRedirects: adminHandler.ProvisionTenantOAuthRedirects,
			AdminCreateClient:                  adminHandler.CreateClient,
			AdminListClients:             adminHandler.ListClients,
			AdminGetClient:               adminHandler.GetClient,
			AdminUpdateClient:            adminHandler.UpdateClient,
			AdminDeleteClient:            adminHandler.DeleteClient,
			AdminRotateKeys:              adminHandler.RotateKeys,
			PublicCreateTenant:           adminHandler.CreateTenantPublic,
			PublicGetTenantBySlug:        adminHandler.GetTenantBySlugPublic,
			AdminCreateIntegrationConfig: adminHandler.CreateIntegrationConfig,
			AdminGetIntegrationConfig:    adminHandler.GetIntegrationConfig,
			AdminListIntegrationConfigs:  adminHandler.ListIntegrationConfigs,
			AdminDeleteIntegrationConfig: adminHandler.DeleteIntegrationConfig,
			AdminUpdateIntegrationStatus: adminHandler.UpdateIntegrationStatus,
			// Tenant member management
			AddTenantMember:       adminHandler.AddTenantMember,
			ListTenantMembers:     adminHandler.ListTenantMembers,
			UpdateTenantMember:    adminHandler.UpdateTenantMember,
			RemoveTenantMember:    adminHandler.RemoveTenantMember,
			S2SListTenantUsers:    adminHandler.S2SListTenantUsers,
			SetUserServicePIN:     adminHandler.SetUserServicePIN,
			DeveloperListClients:  developerHandler.ListClients,
			DeveloperCreateClient: developerHandler.CreateClient,
			// API Key management (service accounts)
			AdminCreateAPIKey: apiKeyHandler.CreateAPIKey,
			AdminListAPIKeys:  apiKeyHandler.ListAPIKeys,
			AdminRevokeAPIKey: apiKeyHandler.RevokeAPIKey,
			ValidateAPIKey:    apiKeyHandler.ValidateAPIKey,
			// App management (GitHub-style S2S tokens; validation merged into ValidateAPIKey)
			AdminCreateApp:      appHandler.CreateApp,
			AdminListApps:       appHandler.ListApps,
			AdminGetApp:         appHandler.GetApp,
			AdminUpdateApp:      appHandler.UpdateApp,
			AdminRevokeApp:      appHandler.RevokeApp,
			AdminDeleteApp:      appHandler.DeleteApp,
			AdminRotateAppToken: appHandler.RotateToken,
			// OTP (email verification for Vera AI ticket flow)
			SendOTP:   authHandler.SendOTP,
			VerifyOTP: authHandler.VerifyOTP,
			// Platform backup management (single shared handler instance)
			ListBackups:          backupHandler.ListBackups,
			DownloadBackup:       backupHandler.DownloadBackup,
			GetBackupSettings:    backupHandler.GetSettings,
			UpdateBackupSettings: backupHandler.UpdateSettings,
			// WebAuthn / passkey biometric login
			WebAuthnBeginRegistration:    webAuthnHandlerFunc(webAuthnHandler, func(h *handlers.WebAuthnHandler) http.HandlerFunc { return h.BeginRegistration }),
			WebAuthnFinishRegistration:   webAuthnHandlerFunc(webAuthnHandler, func(h *handlers.WebAuthnHandler) http.HandlerFunc { return h.FinishRegistration }),
			WebAuthnBeginAuthentication:  webAuthnHandlerFunc(webAuthnHandler, func(h *handlers.WebAuthnHandler) http.HandlerFunc { return h.BeginAuthentication }),
			WebAuthnFinishAuthentication: webAuthnHandlerFunc(webAuthnHandler, func(h *handlers.WebAuthnHandler) http.HandlerFunc { return h.FinishAuthentication }),
			WebAuthnListCredentials:      webAuthnHandlerFunc(webAuthnHandler, func(h *handlers.WebAuthnHandler) http.HandlerFunc { return h.ListCredentials }),
			WebAuthnDeleteCredential:     webAuthnHandlerFunc(webAuthnHandler, func(h *handlers.WebAuthnHandler) http.HandlerFunc { return h.DeleteCredential }),
		},
		RequireAuthHandler: authMiddleware.RequireAuth,
		TryAuthHandler:     authMiddleware.TryAuth,
		RateLimitLogin:     rateLimiter.Limit("login", 60, time.Minute, func(r *http.Request) string { return r.RemoteAddr }),
		RateLimitToken:     rateLimiter.Limit("token", 120, time.Minute, func(r *http.Request) string { return r.RemoteAddr }),
	})

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		Handler:           router,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	// Start NATS subscription sync subscriber (updates denormalised sub fields on tenant)
	var subSubscriber *platformevents.SubscriptionSubscriber
	if natsConn != nil {
		subSubscriber = platformevents.NewSubscriptionSubscriber(entClient, redisClient, cfg.Redis.Namespace, logger)
		if err := subSubscriber.Start(natsConn); err != nil {
			logger.Warn("failed to start subscription subscriber", zap.Error(err))
			subSubscriber = nil
		}
	}

	// Start the platform-wide pg_dumpall DR backup scheduler. The master switch is
	// cfg.Backup.ScheduleEnabled (default true); the actual backup run is still gated by
	// the DB-stored auto_enabled flag (opt-in, default OFF). DSN reuses the same connection
	// string the ent client connects with (cfg.Database.URL).
	platformbackup.NewScheduler(platformBackupSvc, sqlDB, platformbackup.SchedulerConfig{
		Enabled:   cfg.Backup.ScheduleEnabled,
		BackupDir: cfg.Backup.Dir,
		DSN:       cfg.Database.URL,
	}, logger).Start(ctx)

	return &App{
		cfg:                    cfg,
		logger:                 logger,
		entClient:              entClient,
		db:                     sqlDB,
		redis:                  redisClient,
		natsConn:               natsConn,
		outboxPublisher:        outboxPub,
		subscriptionSubscriber: subSubscriber,
		httpServer:             server,
	}, nil
}

// Run starts the HTTP server with TLS if certificates are configured.
func (a *App) Run() error {
	if a.cfg.HTTP.TLSCertFile != "" && a.cfg.HTTP.TLSKeyFile != "" {
		a.logger.Info("starting HTTPS server",
			zap.String("cert", a.cfg.HTTP.TLSCertFile),
			zap.String("key", a.cfg.HTTP.TLSKeyFile),
			zap.String("addr", a.httpServer.Addr),
		)
		return a.httpServer.ListenAndServeTLS(a.cfg.HTTP.TLSCertFile, a.cfg.HTTP.TLSKeyFile)
	}
	a.logger.Info("starting HTTP server", zap.String("addr", a.httpServer.Addr))
	return a.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server and closes resources.
func (a *App) Shutdown(ctx context.Context) error {
	shutdownErr := a.httpServer.Shutdown(ctx)

	// Stop subscribers and outbox publisher
	if a.subscriptionSubscriber != nil {
		a.subscriptionSubscriber.Stop()
	}
	if a.outboxPublisher != nil {
		a.outboxPublisher.Stop()
	}

	// Drain and close NATS
	if a.natsConn != nil {
		a.natsConn.Drain()
		a.natsConn.Close()
	}

	if err := a.entClient.Close(); err != nil {
		a.logger.Warn("failed to close ent client", zap.Error(err))
		if shutdownErr == nil {
			shutdownErr = err
		}
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			a.logger.Warn("failed to close database", zap.Error(err))
			if shutdownErr == nil {
				shutdownErr = err
			}
		}
	}
	if err := a.redis.Close(); err != nil {
		a.logger.Warn("failed to close redis client", zap.Error(err))
		if shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

// webAuthnHandlerFunc returns nil if handler is nil (WebAuthn disabled), or calls f(handler).
func webAuthnHandlerFunc(h *handlers.WebAuthnHandler, f func(*handlers.WebAuthnHandler) http.HandlerFunc) http.HandlerFunc {
	if h == nil {
		return nil
	}
	return f(h)
}
