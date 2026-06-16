package config

import (
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config aggregates all runtime settings.
type Config struct {
	App          AppConfig          `envPrefix:""`
	HTTP         HTTPConfig         `envPrefix:"HTTP_"`
	Database     DatabaseConfig     `envPrefix:""`
	Redis        RedisConfig        `envPrefix:"REDIS_"`
	Token        TokenConfig        `envPrefix:"AUTH_TOKEN_"`
	Security     SecurityConfig     `envPrefix:"AUTH_SECURITY_"`
	Providers    ProvidersConfig    `envPrefix:"AUTH_PROVIDERS_"`
	Subscription SubscriptionConfig `envPrefix:"AUTH_SUBSCRIPTION_"`
	Events       EventsConfig       `envPrefix:"AUTH_EVENTS_"`
	Backup       BackupConfig       `envPrefix:"BACKUP_"`
	WebAuthn     WebAuthnConfig     `envPrefix:"AUTH_WEBAUTHN_"`
}

// BackupConfig points to the internal backup-server that serves PostgreSQL backup files.
// Platform admins can list and download backups via the /api/v1/platform/backups endpoint.
type BackupConfig struct {
	// Internal URL of the backup-server nginx service (ClusterIP, not exposed externally).
	// In K8s: http://backup-server.infra.svc.cluster.local
	ServiceURL string `env:"SERVICE_URL" envDefault:"http://backup-server.infra.svc.cluster.local"`
	// Whether the backup download feature is enabled.
	Enabled bool `env:"ENABLED" envDefault:"true"`
	// ScheduleEnabled is the MASTER switch for the platform pg_dumpall DR scheduler.
	// The actual run is still gated by the DB-stored auto_enabled flag (opt-in, default OFF).
	ScheduleEnabled bool `env:"SCHEDULE_ENABLED" envDefault:"true"`
	// Dir is where the scheduler writes platform_dumpall_*.sql.gz backup files.
	Dir string `env:"DIR" envDefault:"/data/backups"`
}

// EventsConfig holds NATS and outbox publisher settings.
type EventsConfig struct {
	NATSURL          string        `env:"NATS_URL" envDefault:"nats://127.0.0.1:4222"`
	Enabled          bool          `env:"ENABLED" envDefault:"false"`
	OutboxPollPeriod time.Duration `env:"OUTBOX_POLL_PERIOD" envDefault:"5s"`
	OutboxBatchSize  int           `env:"OUTBOX_BATCH_SIZE" envDefault:"100"`
}

// SubscriptionConfig holds settings for subscription-service integration.
type SubscriptionConfig struct {
	BaseURL string        `env:"BASE_URL" envDefault:"http://localhost:4008"`
	APIKey  string        `env:"API_KEY"`
	Timeout time.Duration `env:"TIMEOUT" envDefault:"5s"`
	Enabled bool          `env:"ENABLED" envDefault:"true"`
}

type AppConfig struct {
	Environment string `env:"APP_ENV" envDefault:"development"`
	ServiceName string `env:"APP_NAME" envDefault:"auth-api"`
	AuthUIURL   string `env:"AUTH_UI_URL" envDefault:"https://accounts.codevertexitsolutions.com"`
}

// WebAuthnConfig holds WebAuthn / passkey relying party settings.
type WebAuthnConfig struct {
	RPID          string   `env:"RPID" envDefault:"codevertexitsolutions.com"`
	RPDisplayName string   `env:"RP_DISPLAY_NAME" envDefault:"Codevertex Platform"`
	RPOrigins     []string `env:"RP_ORIGINS" envSeparator:"," envDefault:"https://accounts.codevertexitsolutions.com,https://pos.codevertexitsolutions.com,https://inventory.codevertexitsolutions.com,https://ordersapp.codevertexitsolutions.com"`
}

type HTTPConfig struct {
	Host              string        `env:"HOST" envDefault:"0.0.0.0"`
	Port              int           `env:"PORT" envDefault:"4000"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"120s"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"5s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"25s"`
	TLSCertFile       string        `env:"TLS_CERT_FILE"`
	TLSKeyFile        string        `env:"TLS_KEY_FILE"`
}

type DatabaseConfig struct {
	URL             string        `env:"POSTGRES_URL"`
	MigrateURL      string        `env:"POSTGRES_MIGRATE_URL"` // direct PG for migrate/seed; bypasses PgBouncer transaction mode
	MaxOpenConns    int           `env:"POSTGRES_MAX_OPEN_CONNS" envDefault:"8"`
	MaxIdleConns    int           `env:"POSTGRES_MAX_IDLE_CONNS" envDefault:"3"`
	ConnMaxLifetime time.Duration `env:"POSTGRES_CONN_MAX_LIFETIME" envDefault:"15m"`
	RunMigrations   bool          `env:"POSTGRES_RUN_MIGRATIONS" envDefault:"false"`
}

type RedisConfig struct {
	Addr      string `env:"ADDR" envDefault:"127.0.0.1:6379"`
	Password  string `env:"PASSWORD"`
	DB        int    `env:"DB" envDefault:"0"`
	EnableTLS bool   `env:"ENABLE_TLS" envDefault:"false"`
	Namespace string `env:"NAMESPACE" envDefault:"auth"`
}

type TokenConfig struct {
	Issuer              string        `env:"ISSUER" envDefault:"https://auth.bengobox.local"`
	Audience            string        `env:"AUDIENCE" envDefault:"codevertex"`
	PrivateKeyPath      string        `env:"PRIVATE_KEY_PATH"`
	PublicKeyPath       string        `env:"PUBLIC_KEY_PATH"`
	AccessTokenTTL      time.Duration `env:"ACCESS_TTL" envDefault:"8h"`
	RefreshTokenTTL     time.Duration `env:"REFRESH_TTL" envDefault:"720h"`
	RotateRefreshTokens bool          `env:"ROTATE_REFRESH" envDefault:"true"`
	DefaultScopes       []string      `env:"DEFAULT_SCOPES" envSeparator:"," envDefault:"profile,email,offline_access"`
}

type SecurityConfig struct {
	PasswordMinLength   int      `env:"PASSWORD_MIN_LENGTH" envDefault:"12"`
	Argon2Time          uint32   `env:"ARGON2_TIME" envDefault:"3"`
	Argon2Memory        uint32   `env:"ARGON2_MEMORY" envDefault:"65536"`
	Argon2Threads       uint8    `env:"ARGON2_THREADS" envDefault:"2"`
	Argon2KeyLength     uint32   `env:"ARGON2_KEY_LENGTH" envDefault:"32"`
	OAuthStateSecret    string   `env:"OAUTH_STATE_SECRET"`
	EncryptionKey       string   `env:"ENCRYPTION_KEY"`                                                                                       // 32-byte hex string or raw key
	CookieDomain        string   `env:"COOKIE_DOMAIN" envDefault:".codevertexitsolutions.com"`                                                // Domain for session cookies
	LogoutRedirectHosts []string `env:"LOGOUT_REDIRECT_HOSTS" envSeparator:"," envDefault:"theurbanloftcafe.com,ordersapp.codevertexitsolutions.com,accounts.codevertexitsolutions.com,sso.codevertexitsolutions.com,notifications.codevertexitsolutions.com,books.codevertexitsolutions.com,pricing.codevertexitsolutions.com,pos.codevertexitsolutions.com,inventory.codevertexitsolutions.com,logistics.codevertexitsolutions.com,riderapp.codevertexitsolutions.com,localhost"`
}

type ProvidersConfig struct {
	Google    GoogleProviderConfig    `envPrefix:"GOOGLE_"`
	GitHub    GitHubProviderConfig    `envPrefix:"GITHUB_"`
	Microsoft MicrosoftProviderConfig `envPrefix:"MICROSOFT_"`
	Apple     AppleProviderConfig     `envPrefix:"APPLE_"`
}

type GoogleProviderConfig struct {
	Enabled        bool     `env:"ENABLED" envDefault:"false"`
	ClientID       string   `env:"CLIENT_ID"`
	ClientSecret   string   `env:"CLIENT_SECRET"`
	RedirectURL    string   `env:"REDIRECT_URL"`
	AllowedDomains []string `env:"ALLOWED_DOMAINS" envSeparator:","`
}

type GitHubProviderConfig struct {
	Enabled        bool     `env:"ENABLED" envDefault:"false"`
	ClientID       string   `env:"CLIENT_ID"`
	ClientSecret   string   `env:"CLIENT_SECRET"`
	RedirectURL    string   `env:"REDIRECT_URL"`
	AllowedDomains []string `env:"ALLOWED_DOMAINS" envSeparator:","`
}

type MicrosoftProviderConfig struct {
	Enabled        bool     `env:"ENABLED" envDefault:"false"`
	ClientID       string   `env:"CLIENT_ID"`
	ClientSecret   string   `env:"CLIENT_SECRET"`
	RedirectURL    string   `env:"REDIRECT_URL"`
	AllowedDomains []string `env:"ALLOWED_DOMAINS" envSeparator:","`
}

type AppleProviderConfig struct {
	Enabled        bool     `env:"ENABLED" envDefault:"false"`
	ClientID       string   `env:"CLIENT_ID"`
	ClientSecret   string   `env:"CLIENT_SECRET"`
	RedirectURL    string   `env:"REDIRECT_URL"`
	AllowedDomains []string `env:"ALLOWED_DOMAINS" envSeparator:","`
}

// Load parses environment variables into Config and performs validation.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}

	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("POSTGRES_URL is required")
	}
	if cfg.Token.PrivateKeyPath == "" || cfg.Token.PublicKeyPath == "" {
		return nil, fmt.Errorf("AUTH_TOKEN_PRIVATE_KEY_PATH and AUTH_TOKEN_PUBLIC_KEY_PATH are required")
	}

	// OAuth provider credentials are loaded from DB (integration_configs) at runtime, not from env.
	// When any provider is enabled, only OAuthStateSecret is required (for CSRF protection).
	oauthEnabled := cfg.Providers.Google.Enabled || cfg.Providers.GitHub.Enabled ||
		cfg.Providers.Microsoft.Enabled || cfg.Providers.Apple.Enabled
	if oauthEnabled && cfg.Security.OAuthStateSecret == "" {
		return nil, fmt.Errorf("AUTH_SECURITY_OAUTH_STATE_SECRET is required when any OAuth provider is enabled")
	}
	// Standardized NATS URL: accept EVENTS_NATS_URL when AUTH_EVENTS_NATS_URL is not set
	if cfg.Events.NATSURL == "" {
		cfg.Events.NATSURL = os.Getenv("EVENTS_NATS_URL")
	}
	// Standardized S2S key: AUTH_SUBSCRIPTION_API_KEY → INTERNAL_SERVICE_KEY (uniform across all services)
	if cfg.Subscription.APIKey == "" {
		cfg.Subscription.APIKey = os.Getenv("INTERNAL_SERVICE_KEY")
	}
	return cfg, nil
}

// LoadDatabaseOnly parses only database-related environment variables.
// Use this for migrations and setup scripts that don't need full config validation.
func LoadDatabaseOnly() (DatabaseConfig, error) {
	type dbOnlyConfig struct {
		Database DatabaseConfig `envPrefix:""`
	}
	cfg := &dbOnlyConfig{}
	if err := env.Parse(cfg); err != nil {
		return DatabaseConfig{}, fmt.Errorf("parse env: %w", err)
	}
	if cfg.Database.URL == "" {
		return DatabaseConfig{}, fmt.Errorf("POSTGRES_URL is required")
	}
	return cfg.Database, nil
}

// SeedConfig contains only what's needed for seeding (database + security + token issuer).
type SeedConfig struct {
	Database DatabaseConfig `envPrefix:""`
	Security SecurityConfig `envPrefix:"AUTH_SECURITY_"`
	Token    TokenConfig    `envPrefix:"AUTH_TOKEN_"`
}

// LoadForSeed parses config needed for seeding without OAuth validation.
func LoadForSeed() (*SeedConfig, error) {
	cfg := &SeedConfig{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}
	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("POSTGRES_URL is required")
	}
	return cfg, nil
}
