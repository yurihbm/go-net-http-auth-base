package config

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"time"

	"go-net-http-auth-base/internal/env"
)

const (
	defaultPort = "8080"

	minJWTSecretLength = 32

	defaultDBMaxConns          = int32(25)
	defaultDBMinConns          = int32(5)
	defaultDBMaxConnLifetime   = time.Hour
	defaultDBMaxConnIdleTime   = 30 * time.Minute
	defaultDBHealthCheckPeriod = time.Minute
	defaultDBConnectTimeout    = 15 * time.Second

	defaultDBSlowQueryThreshold = 200 * time.Millisecond

	defaultDBStatsLogInterval = 30 * time.Second

	defaultRateLimitRequestsPerSecond = 20.0
	defaultRateLimitBurst             = 50

	defaultSessionMaxAge      = 30 * 24 * time.Hour
	defaultMaxSessionsPerUser = 10

	defaultOTelServiceName = "go-net-http-auth-base"
	defaultOTelEndpoint    = "http://localhost:4318"
	defaultOTelSampleRatio = 1.0
)

// Config is the single source of truth for every environment variable the
// application reads. It is built once at startup via Load.
type Config struct {
	Env    string
	Port   string
	APIURL string

	JWTSecret          string
	SessionMaxAge      time.Duration
	MaxSessionsPerUser int

	Database  DatabaseConfig
	OAuth     OAuthConfig
	CORS      CORSConfig
	RateLimit RateLimitConfig
	Email     EmailConfig
	Telemetry TelemetryConfig

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

	SlowQueryThreshold time.Duration
}

type OAuthProviderCredentials struct {
	ClientID     string
	ClientSecret string
}

type OAuthConfig struct {
	Google    OAuthProviderCredentials
	GitHub    OAuthProviderCredentials
	Microsoft OAuthProviderCredentials

	CallbackAllowList []string
}

type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
}

type EmailConfig struct {
	ResendAPIKey    string
	From            string
	VerificationURL string
}

type TelemetryConfig struct {
	Enabled     bool
	ServiceName string
	Endpoint    string
	SampleRatio float64
}

type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

type envReader struct {
	err error
}

func read[T any](r *envReader, lookup func(string, T) (T, error), key string, defaultVal T) T {
	value, err := lookup(key, defaultVal)
	if err != nil && r.err == nil {
		r.err = err
	}
	return value
}

// Load reads and parses every environment variable the application depends
// on, applying defaults where applicable. It returns an error if a required
// variable (DATABASE_URL, JWT_SECRET) is missing or any value is malformed
// or out of range.
func Load() (*Config, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET not set in environment")
	}
	if len(jwtSecret) < minJWTSecretLength {
		return nil, fmt.Errorf("JWT_SECRET must be at least %d characters long", minJWTSecretLength)
	}

	dbCfg, err := LoadDatabaseConfig()
	if err != nil {
		return nil, err
	}
	if dbCfg.URL == "" {
		return nil, errors.New("DATABASE_URL not set in environment")
	}

	port := os.Getenv("API_PORT")
	if port == "" {
		port = defaultPort
	}

	r := &envReader{}

	cfg := &Config{
		Env:    os.Getenv("API_ENV"),
		Port:   port,
		APIURL: os.Getenv("API_URL"),

		JWTSecret:          jwtSecret,
		SessionMaxAge:      read(r, env.LookupDuration, "SESSION_MAX_AGE", defaultSessionMaxAge),
		MaxSessionsPerUser: read(r, env.LookupInt, "MAX_SESSIONS_PER_USER", defaultMaxSessionsPerUser),

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
			CallbackAllowList: parseCommaSeparated(os.Getenv("OAUTH_CALLBACK_ALLOW_LIST")),
		},

		CORS: CORSConfig{
			AllowedOrigins: parseCommaSeparated(os.Getenv("CORS_ALLOWED_ORIGINS")),
			AllowedMethods: parseCommaSeparated(os.Getenv("CORS_ALLOWED_METHODS")),
		},

		RateLimit: RateLimitConfig{
			RequestsPerSecond: read(r, env.LookupFloat, "RATE_LIMIT_REQUESTS_PER_SECOND", defaultRateLimitRequestsPerSecond),
			Burst:             read(r, env.LookupInt, "RATE_LIMIT_BURST", defaultRateLimitBurst),
		},

		Email: EmailConfig{
			ResendAPIKey:    os.Getenv("RESEND_API_KEY"),
			From:            os.Getenv("EMAIL_FROM"),
			VerificationURL: os.Getenv("EMAIL_VERIFICATION_URL"),
		},

		Telemetry: TelemetryConfig{
			Enabled:     read(r, env.LookupBool, "OTEL_ENABLED", false),
			ServiceName: valueOrDefault(os.Getenv("OTEL_SERVICE_NAME"), defaultOTelServiceName),
			Endpoint:    valueOrDefault(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), defaultOTelEndpoint),
			SampleRatio: read(r, env.LookupFloat, "OTEL_TRACES_SAMPLER_ARG", defaultOTelSampleRatio),
		},

		DBStatsLogInterval: read(r, env.LookupDuration, "DB_STATS_LOG_INTERVAL", defaultDBStatsLogInterval),
	}

	if r.err != nil {
		return nil, r.err
	}

	if cfg.SessionMaxAge <= 0 {
		return nil, errors.New("SESSION_MAX_AGE must be positive")
	}

	if cfg.MaxSessionsPerUser <= 0 {
		return nil, errors.New("MAX_SESSIONS_PER_USER must be positive")
	}

	if rps := cfg.RateLimit.RequestsPerSecond; !(rps > 0) || math.IsInf(rps, 0) {
		return nil, errors.New("RATE_LIMIT_REQUESTS_PER_SECOND must be positive")
	}

	if cfg.RateLimit.Burst <= 0 {
		return nil, errors.New("RATE_LIMIT_BURST must be positive")
	}

	if cfg.DBStatsLogInterval <= 0 {
		return nil, errors.New("DB_STATS_LOG_INTERVAL must be positive")
	}

	if ratio := cfg.Telemetry.SampleRatio; !(ratio >= 0 && ratio <= 1) {
		return nil, errors.New("OTEL_TRACES_SAMPLER_ARG must be between 0 and 1")
	}

	if cfg.Telemetry.Enabled {
		endpoint, err := url.Parse(cfg.Telemetry.Endpoint)
		if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
			return nil, errors.New("OTEL_EXPORTER_OTLP_ENDPOINT must be a valid http or https URL")
		}
	}

	if cfg.IsProduction() && len(cfg.OAuth.CallbackAllowList) == 0 {
		return nil, errors.New("OAUTH_CALLBACK_ALLOW_LIST must not be empty in production")
	}

	if !cfg.IsDevelopment() {
		required := []struct{ name, value string }{
			{"RESEND_API_KEY", cfg.Email.ResendAPIKey},
			{"EMAIL_FROM", cfg.Email.From},
			{"EMAIL_VERIFICATION_URL", cfg.Email.VerificationURL},
		}
		for _, v := range required {
			if v.value == "" {
				return nil, fmt.Errorf("%s not set in environment", v.name)
			}
		}
	}

	return cfg, nil
}

// LoadDatabaseConfig reads the database pool settings from environment
// variables, applying defaults where unset and returning an error for
// malformed or out-of-range values. Unlike Load, it does not validate that
// DATABASE_URL is present, so it can also be used by test helpers that set
// DATABASE_URL to a container connection string at runtime.
func LoadDatabaseConfig() (DatabaseConfig, error) {
	r := &envReader{}

	cfg := DatabaseConfig{
		URL:               os.Getenv("DATABASE_URL"),
		MaxConns:          read(r, env.LookupInt32, "DB_MAX_CONNS", defaultDBMaxConns),
		MinConns:          read(r, env.LookupInt32, "DB_MIN_CONNS", defaultDBMinConns),
		MaxConnLifetime:   read(r, env.LookupDuration, "DB_MAX_CONN_LIFETIME", defaultDBMaxConnLifetime),
		MaxConnIdleTime:   read(r, env.LookupDuration, "DB_MAX_CONN_IDLE_TIME", defaultDBMaxConnIdleTime),
		HealthCheckPeriod: read(r, env.LookupDuration, "DB_HEALTH_CHECK_PERIOD", defaultDBHealthCheckPeriod),
		ConnectTimeout:    read(r, env.LookupDuration, "DB_CONNECT_TIMEOUT", defaultDBConnectTimeout),

		SlowQueryThreshold: read(r, env.LookupDuration, "DB_SLOW_QUERY_THRESHOLD", defaultDBSlowQueryThreshold),
	}
	if r.err != nil {
		return DatabaseConfig{}, r.err
	}

	if cfg.MaxConns <= 0 {
		return DatabaseConfig{}, errors.New("DB_MAX_CONNS must be positive")
	}
	if cfg.MinConns < 0 {
		return DatabaseConfig{}, errors.New("DB_MIN_CONNS must not be negative")
	}

	if cfg.MinConns > cfg.MaxConns {
		return DatabaseConfig{}, errors.New("DB_MIN_CONNS must not exceed DB_MAX_CONNS")
	}
	if cfg.SlowQueryThreshold < 0 {
		return DatabaseConfig{}, errors.New("DB_SLOW_QUERY_THRESHOLD must not be negative")
	}

	durations := []struct {
		name  string
		value time.Duration
	}{
		{"DB_MAX_CONN_LIFETIME", cfg.MaxConnLifetime},
		{"DB_MAX_CONN_IDLE_TIME", cfg.MaxConnIdleTime},
		{"DB_HEALTH_CHECK_PERIOD", cfg.HealthCheckPeriod},
		{"DB_CONNECT_TIMEOUT", cfg.ConnectTimeout},
	}
	for _, d := range durations {
		if d.value <= 0 {
			return DatabaseConfig{}, fmt.Errorf("%s must be positive", d.name)
		}
	}

	return cfg, nil
}

func (c *Config) IsProduction() bool {
	return c.Env == "production"
}

func (c *Config) IsDevelopment() bool {
	return c.Env == "development"
}

func valueOrDefault(value, defaultVal string) string {
	if value == "" {
		return defaultVal
	}
	return value
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
