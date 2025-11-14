package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config aggregates all runtime settings.
type Config struct {
	App       AppConfig       `envPrefix:"AUTH_"`
	HTTP      HTTPConfig      `envPrefix:"AUTH_HTTP_"`
	Database  DatabaseConfig  `envPrefix:"AUTH_DB_"`
	Redis     RedisConfig     `envPrefix:"AUTH_REDIS_"`
	Token     TokenConfig     `envPrefix:"AUTH_TOKEN_"`
	Security  SecurityConfig  `envPrefix:"AUTH_SECURITY_"`
	Providers ProvidersConfig `envPrefix:"AUTH_PROVIDERS_"`
}

type AppConfig struct {
	Environment string `env:"ENV" envDefault:"development"`
	ServiceName string `env:"SERVICE_NAME" envDefault:"auth-service"`
}

type HTTPConfig struct {
	Host              string        `env:"HOST" envDefault:"0.0.0.0"`
	Port              int           `env:"PORT" envDefault:"4101"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"120s"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"5s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"25s"`
}

type DatabaseConfig struct {
	URL             string        `env:"URL"`
	MaxOpenConns    int           `env:"MAX_OPEN_CONNS" envDefault:"20"`
	MaxIdleConns    int           `env:"MAX_IDLE_CONNS" envDefault:"5"`
	ConnMaxLifetime time.Duration `env:"CONN_MAX_LIFETIME" envDefault:"30m"`
	RunMigrations   bool          `env:"RUN_MIGRATIONS" envDefault:"true"`
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
	Audience            string        `env:"AUDIENCE" envDefault:"bengobox"`
	PrivateKeyPath      string        `env:"PRIVATE_KEY_PATH"`
	PublicKeyPath       string        `env:"PUBLIC_KEY_PATH"`
	AccessTokenTTL      time.Duration `env:"ACCESS_TTL" envDefault:"15m"`
	RefreshTokenTTL     time.Duration `env:"REFRESH_TTL" envDefault:"720h"`
	RotateRefreshTokens bool          `env:"ROTATE_REFRESH" envDefault:"true"`
	DefaultScopes       []string      `env:"DEFAULT_SCOPES" envSeparator:"," envDefault:"profile,email,offline_access"`
}

type SecurityConfig struct {
	PasswordMinLength int    `env:"PASSWORD_MIN_LENGTH" envDefault:"12"`
	Argon2Time        uint32 `env:"ARGON2_TIME" envDefault:"3"`
	Argon2Memory      uint32 `env:"ARGON2_MEMORY" envDefault:"65536"`
	Argon2Threads     uint8  `env:"ARGON2_THREADS" envDefault:"2"`
	Argon2KeyLength   uint32 `env:"ARGON2_KEY_LENGTH" envDefault:"32"`
	OAuthStateSecret  string `env:"OAUTH_STATE_SECRET"`
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
		return nil, fmt.Errorf("AUTH_DB_URL is required")
	}
	if cfg.Token.PrivateKeyPath == "" || cfg.Token.PublicKeyPath == "" {
		return nil, fmt.Errorf("AUTH_TOKEN_PRIVATE_KEY_PATH and AUTH_TOKEN_PUBLIC_KEY_PATH are required")
	}

	if cfg.Providers.Google.Enabled {
		if cfg.Providers.Google.ClientID == "" || cfg.Providers.Google.ClientSecret == "" || cfg.Providers.Google.RedirectURL == "" {
			return nil, fmt.Errorf("google oauth requires CLIENT_ID, CLIENT_SECRET, and REDIRECT_URL")
		}
		if cfg.Security.OAuthStateSecret == "" {
			return nil, fmt.Errorf("AUTH_SECURITY_OAUTH_STATE_SECRET is required when Google OAuth is enabled")
		}
	}
	if cfg.Providers.GitHub.Enabled {
		if cfg.Providers.GitHub.ClientID == "" || cfg.Providers.GitHub.ClientSecret == "" || cfg.Providers.GitHub.RedirectURL == "" {
			return nil, fmt.Errorf("github oauth requires CLIENT_ID, CLIENT_SECRET, and REDIRECT_URL")
		}
		if cfg.Security.OAuthStateSecret == "" {
			return nil, fmt.Errorf("AUTH_SECURITY_OAUTH_STATE_SECRET is required when GitHub OAuth is enabled")
		}
	}
	if cfg.Providers.Microsoft.Enabled {
		if cfg.Providers.Microsoft.ClientID == "" || cfg.Providers.Microsoft.ClientSecret == "" || cfg.Providers.Microsoft.RedirectURL == "" {
			return nil, fmt.Errorf("microsoft oauth requires CLIENT_ID, CLIENT_SECRET, and REDIRECT_URL")
		}
		if cfg.Security.OAuthStateSecret == "" {
			return nil, fmt.Errorf("AUTH_SECURITY_OAUTH_STATE_SECRET is required when Microsoft OAuth is enabled")
		}
	}
	if cfg.Providers.Apple.Enabled {
		if cfg.Providers.Apple.ClientID == "" || cfg.Providers.Apple.ClientSecret == "" || cfg.Providers.Apple.RedirectURL == "" {
			return nil, fmt.Errorf("apple oauth requires CLIENT_ID, CLIENT_SECRET, and REDIRECT_URL")
		}
		if cfg.Security.OAuthStateSecret == "" {
			return nil, fmt.Errorf("AUTH_SECURITY_OAUTH_STATE_SECRET is required when Apple OAuth is enabled")
		}
	}
	return cfg, nil
}
