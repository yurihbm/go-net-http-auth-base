package config

import (
	"errors"
	"os"
	"strings"
	"time"

	"go-net-http-auth-base/internal/env"
)

const (
	defaultPort = "8080"

	defaultDBMaxConns          = int32(25)
	defaultDBMinConns          = int32(5)
	defaultDBMaxConnLifetime   = time.Hour
	defaultDBMaxConnIdleTime   = 30 * time.Minute
	defaultDBHealthCheckPeriod = time.Minute
	defaultDBConnectTimeout    = 15 * time.Second

	defaultDBStatsLogInterval = 30 * time.Second

	defaultRateLimitRequestsPerSecond = 20.0
	defaultRateLimitBurst             = 50
)

// Config is the single source of truth for every environment variable the
// application reads. It is built once at startup via Load.
type Config struct {
	Env    string
	Port   string
	APIURL string

	JWTSecret string

	Database  DatabaseConfig
	OAuth     OAuthConfig
	CORS      CORSConfig
	RateLimit RateLimitConfig

	DBStatsLogInterval time.Duration
}

// DatabaseConfig holds connection pool settings parsed from environment variables.
type DatabaseConfig struct {
	URL               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}

type OAuthProviderCredentials struct {
	ClientID     string
	ClientSecret string
}

type OAuthConfig struct {
	Google    OAuthProviderCredentials
	GitHub    OAuthProviderCredentials
	Microsoft OAuthProviderCredentials
}

type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
}

type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

// Load reads and parses every environment variable the application depends
// on, applying defaults where applicable. It returns an error if a required
// variable (DATABASE_URL, JWT_SECRET) is missing.
func Load() (*Config, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET not set in environment")
	}

	dbCfg := LoadDatabaseConfig()
	if dbCfg.URL == "" {
		return nil, errors.New("DATABASE_URL not set in environment")
	}

	port := os.Getenv("API_PORT")
	if port == "" {
		port = defaultPort
	}

	return &Config{
		Env:    os.Getenv("API_ENV"),
		Port:   port,
		APIURL: os.Getenv("API_URL"),

		JWTSecret: jwtSecret,

		Database: dbCfg,

		OAuth: OAuthConfig{
			Google: OAuthProviderCredentials{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			},
			GitHub: OAuthProviderCredentials{
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			},
			Microsoft: OAuthProviderCredentials{
				ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
				ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
			},
		},

		CORS: CORSConfig{
			AllowedOrigins: parseCommaSeparated(os.Getenv("CORS_ALLOWED_ORIGINS")),
			AllowedMethods: parseCommaSeparated(os.Getenv("CORS_ALLOWED_METHODS")),
		},

		RateLimit: RateLimitConfig{
			RequestsPerSecond: env.GetEnvAsFloat("RATE_LIMIT_REQUESTS_PER_SECOND", defaultRateLimitRequestsPerSecond),
			Burst:             env.GetEnvAsInt("RATE_LIMIT_BURST", defaultRateLimitBurst),
		},

		DBStatsLogInterval: env.GetEnvAsDuration("DB_STATS_LOG_INTERVAL", defaultDBStatsLogInterval),
	}, nil
}

// LoadDatabaseConfig reads the database pool settings from environment
// variables, applying defaults where unset. Unlike Load, it does not
// validate that DATABASE_URL is present, so it can also be used by test
// helpers that set DATABASE_URL to a container connection string at runtime.
//
// MinConns is capped to MaxConns if it would otherwise exceed it.
func LoadDatabaseConfig() DatabaseConfig {
	cfg := DatabaseConfig{
		URL:               os.Getenv("DATABASE_URL"),
		MaxConns:          env.GetEnvAsInt32("DB_MAX_CONNS", defaultDBMaxConns),
		MinConns:          env.GetEnvAsInt32("DB_MIN_CONNS", defaultDBMinConns),
		MaxConnLifetime:   env.GetEnvAsDuration("DB_MAX_CONN_LIFETIME", defaultDBMaxConnLifetime),
		MaxConnIdleTime:   env.GetEnvAsDuration("DB_MAX_CONN_IDLE_TIME", defaultDBMaxConnIdleTime),
		HealthCheckPeriod: env.GetEnvAsDuration("DB_HEALTH_CHECK_PERIOD", defaultDBHealthCheckPeriod),
		ConnectTimeout:    env.GetEnvAsDuration("DB_CONNECT_TIMEOUT", defaultDBConnectTimeout),
	}

	if cfg.MinConns > cfg.MaxConns {
		cfg.MinConns = cfg.MaxConns
	}

	return cfg
}

func (c *Config) IsProduction() bool {
	return c.Env == "production"
}

func (c *Config) IsDevelopment() bool {
	return c.Env == "development"
}

func parseCommaSeparated(value string) []string {
	if value == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	trimmed := make([]string, len(parts))
	for i, part := range parts {
		trimmed[i] = strings.TrimSpace(part)
	}

	return trimmed
}
