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
	"github.com/bengobox/auth-api/internal/modules/outbox"
	"github.com/bengobox/auth-api/internal/password"
	platformevents "github.com/bengobox/auth-api/internal/platform/events"
	githubprovider "github.com/bengobox/auth-api/internal/providers/github"
	googleprovider "github.com/bengobox/auth-api/internal/providers/google"
	microsoftprovider "github.com/bengobox/auth-api/internal/providers/microsoft"
	"github.com/bengobox/auth-api/internal/revocation"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/services/mfa"
	"github.com/bengobox/auth-api/internal/services/oidc"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// App wires core dependencies and exposes server lifecycle controls.
type App struct {
	cfg             *config.Config
	logger          *zap.Logger
	entClient       *ent.Client
	db              *sql.DB
	redis           *redis.Client
	natsConn        *nats.Conn
	outboxPublisher *outbox.Publisher
	httpServer      *http.Server
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

	tokenSvc, err := token.NewService(cfg.Token)
	if err != nil {
		return nil, err
	}

	googleProvider, err := googleprovider.New(cfg.Providers.Google)
	if err != nil {
		return nil, err
	}
	githubProvider, err := githubprovider.New(cfg.Providers.GitHub)
	if err != nil {
		return nil, err
	}
	microsoftProvider, err := microsoftprovider.New(cfg.Providers.Microsoft)
	if err != nil {
		return nil, err
	}

	hasher := password.NewHasher(cfg.Security)
	auditor := audit.New(entClient, logger)

	// Initialize subscription client for JWT enrichment (optional)
	var subClient *subscriptionclient.Client
	if cfg.Subscription.Enabled && cfg.Subscription.BaseURL != "" {
		subClient = subscriptionclient.NewClient(subscriptionclient.Config{
			BaseURL: cfg.Subscription.BaseURL,
			APIKey:  cfg.Subscription.APIKey,
			Timeout: cfg.Subscription.Timeout,
		}, logger)
		logger.Info("subscription client initialized",
			zap.String("base_url", cfg.Subscription.BaseURL),
		)
	}

	// Initialize NATS event publishing (optional)
	var natsConn *nats.Conn
	var outboxPub *outbox.Publisher
	if cfg.Events.Enabled {
		natsConn, err = platformevents.Connect(cfg.Events)
		if err != nil {
			return nil, fmt.Errorf("connect to NATS: %w", err)
		}
		logger.Info("NATS connection established",
			zap.String("url", cfg.Events.NATSURL),
		)

		outboxRepo := outbox.NewEntRepository(entClient, sqlDB)
		outboxNatsPublisher := platformevents.NewOutboxPublisher(natsConn, logger)
		outboxPub = outbox.NewPublisher(outboxRepo, outboxNatsPublisher, logger, outbox.PublisherConfig{
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
	})

	authHandler := handlers.NewAuthHandler(authService, logger)
	revocationStore := revocation.New(redisClient, cfg.Redis.Namespace)
	authMiddleware := httpmiddleware.NewAuth(authService, revocationStore)
	rateLimiter := httpmiddleware.NewRateLimiter(redisClient, cfg.Redis.Namespace)
	oidcService := oidc.New(entClient, tokenSvc, cfg)
	oidcHandler := handlers.NewOIDCHandlerWithRolesPermissions(cfg, oidcService, authMiddleware, tokenSvc, authService, logger)
	mfaService := mfa.New(entClient, cfg.Token.Issuer)
	mfaHandler := handlers.NewMFAHandler(mfaService, logger)
	adminHandler := handlers.NewAdminHandler(entClient, tokenSvc, logger)
	developerHandler := handlers.NewDeveloperHandler(entClient, logger)
	apiKeyHandler := handlers.NewAPIKeyHandler(entClient, logger)

	router := httpapi.NewRouter(httpapi.RouterDeps{
		HealthHandler:  handlers.Health,
		MetricsHandler: promhttp.Handler(),
		AuthHandlers: httpapi.AuthHandlers{
			Register:                     authHandler.Register,
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
			ListSessions:                 authHandler.ListSessions,
			RevokeSession:                authHandler.RevokeSession,
			RevokeAllSessions:            authHandler.RevokeAllSessions,
			AdminUpsertEntitlement:       adminHandler.UpsertEntitlement,
			AdminListEntitlements:        adminHandler.ListEntitlements,
			AdminIncrementUsage:          adminHandler.IncrementUsage,
			AdminCreateTenant:            adminHandler.CreateTenant,
			AdminListTenants:             adminHandler.ListTenants,
			AdminCreateClient:            adminHandler.CreateClient,
			AdminListClients:             adminHandler.ListClients,
			AdminRotateKeys:              adminHandler.RotateKeys,
			PublicCreateTenant:           adminHandler.CreateTenantPublic,
			PublicGetTenantBySlug:        adminHandler.GetTenantBySlugPublic,
			AdminCreateIntegrationConfig: adminHandler.CreateIntegrationConfig,
			AdminGetIntegrationConfig:    adminHandler.GetIntegrationConfig,
			AdminListIntegrationConfigs:  adminHandler.ListIntegrationConfigs,
			AdminDeleteIntegrationConfig: adminHandler.DeleteIntegrationConfig,
			// Tenant member management
			AddTenantMember:       adminHandler.AddTenantMember,
			ListTenantMembers:     adminHandler.ListTenantMembers,
			UpdateTenantMember:    adminHandler.UpdateTenantMember,
			RemoveTenantMember:    adminHandler.RemoveTenantMember,
			DeveloperListClients:  developerHandler.ListClients,
			DeveloperCreateClient: developerHandler.CreateClient,
			// API Key management (service accounts)
			AdminCreateAPIKey: apiKeyHandler.CreateAPIKey,
			AdminListAPIKeys:  apiKeyHandler.ListAPIKeys,
			AdminRevokeAPIKey: apiKeyHandler.RevokeAPIKey,
			ValidateAPIKey:    apiKeyHandler.ValidateAPIKey,
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

	return &App{
		cfg:             cfg,
		logger:          logger,
		entClient:       entClient,
		db:              sqlDB,
		redis:           redisClient,
		natsConn:        natsConn,
		outboxPublisher: outboxPub,
		httpServer:      server,
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

	// Stop outbox publisher first
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
