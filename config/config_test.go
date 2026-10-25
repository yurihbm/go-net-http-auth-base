package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go-net-http-auth-base/config"
)

const validJWTSecret = "test-secret-with-at-least-32-characters"

func TestLoad(t *testing.T) {
	t.Run("returns error when DATABASE_URL is missing", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "")

		cfg, err := config.Load()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DATABASE_URL")
		assert.Nil(t, cfg)
	})

	t.Run("returns error when JWT_SECRET is missing", func(t *testing.T) {
		t.Setenv("JWT_SECRET", "")
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")

		cfg, err := config.Load()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "JWT_SECRET")
		assert.Nil(t, cfg)
	})

	t.Run("returns error when JWT_SECRET is shorter than the minimum length", func(t *testing.T) {
		t.Setenv("JWT_SECRET", "short-secret")
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")

		cfg, err := config.Load()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "JWT_SECRET")
		assert.Contains(t, err.Error(), "32")
		assert.Nil(t, cfg)
	})

	t.Run("returns error in production when OAUTH_CALLBACK_ALLOW_LIST is empty", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "production")
		t.Setenv("OAUTH_CALLBACK_ALLOW_LIST", "")

		cfg, err := config.Load()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "OAUTH_CALLBACK_ALLOW_LIST")
		assert.Nil(t, cfg)
	})

	t.Run("allows empty OAUTH_CALLBACK_ALLOW_LIST outside production", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "development")
		t.Setenv("OAUTH_CALLBACK_ALLOW_LIST", "")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Empty(t, cfg.OAuth.CallbackAllowList)
	})

	t.Run("applies defaults for optional vars", func(t *testing.T) {
		t.Setenv("API_ENV", "development")
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_PORT", "")
		t.Setenv("RATE_LIMIT_REQUESTS_PER_SECOND", "")
		t.Setenv("RATE_LIMIT_BURST", "")
		t.Setenv("OAUTH_CALLBACK_ALLOW_LIST", "")
		t.Setenv("CORS_ALLOWED_ORIGINS", "")
		t.Setenv("CORS_ALLOWED_METHODS", "")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, "8080", cfg.Port)
		assert.Equal(t, 20.0, cfg.RateLimit.RequestsPerSecond)
		assert.Equal(t, 50, cfg.RateLimit.Burst)
		assert.Equal(t, []string{}, cfg.OAuth.CallbackAllowList)
		assert.Equal(t, []string{}, cfg.CORS.AllowedOrigins)
		assert.Equal(t, []string{}, cfg.CORS.AllowedMethods)
	})

	t.Run("reads and parses all optional vars", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "production")
		t.Setenv("API_PORT", "9090")
		t.Setenv("API_URL", "https://api.example.com")
		t.Setenv("GOOGLE_CLIENT_ID", "google-id")
		t.Setenv("GOOGLE_CLIENT_SECRET", "google-secret")
		t.Setenv("GITHUB_CLIENT_ID", "github-id")
		t.Setenv("GITHUB_CLIENT_SECRET", "github-secret")
		t.Setenv("MICROSOFT_CLIENT_ID", "microsoft-id")
		t.Setenv("MICROSOFT_CLIENT_SECRET", "microsoft-secret")
		t.Setenv("OAUTH_CALLBACK_ALLOW_LIST", "http://a.com/cb, http://b.com/cb")
		t.Setenv("CORS_ALLOWED_ORIGINS", "http://a.com, http://b.com")
		t.Setenv("CORS_ALLOWED_METHODS", "GET, POST")
		t.Setenv("RATE_LIMIT_REQUESTS_PER_SECOND", "5.5")
		t.Setenv("RATE_LIMIT_BURST", "10")
		t.Setenv("DB_STATS_LOG_INTERVAL", "1m")
		t.Setenv("RESEND_API_KEY", "re_key")
		t.Setenv("EMAIL_FROM", "no-reply@example.com")
		t.Setenv("EMAIL_VERIFICATION_URL", "https://app.example.com/verify")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, "production", cfg.Env)
		assert.True(t, cfg.IsProduction())
		assert.False(t, cfg.IsDevelopment())
		assert.Equal(t, "9090", cfg.Port)
		assert.Equal(t, "https://api.example.com", cfg.APIURL)
		assert.Equal(t, validJWTSecret, cfg.JWTSecret)
		assert.Equal(t, config.OAuthProviderCredentials{ClientID: "google-id", ClientSecret: "google-secret"}, cfg.OAuth.Google)
		assert.Equal(t, config.OAuthProviderCredentials{ClientID: "github-id", ClientSecret: "github-secret"}, cfg.OAuth.GitHub)
		assert.Equal(t, config.OAuthProviderCredentials{ClientID: "microsoft-id", ClientSecret: "microsoft-secret"}, cfg.OAuth.Microsoft)
		assert.Equal(t, []string{"http://a.com/cb", "http://b.com/cb"}, cfg.OAuth.CallbackAllowList)
		assert.Equal(t, []string{"http://a.com", "http://b.com"}, cfg.CORS.AllowedOrigins)
		assert.Equal(t, []string{"GET", "POST"}, cfg.CORS.AllowedMethods)
		assert.Equal(t, 5.5, cfg.RateLimit.RequestsPerSecond)
		assert.Equal(t, 10, cfg.RateLimit.Burst)
		assert.Equal(t, time.Minute, cfg.DBStatsLogInterval)
		assert.Equal(t, config.EmailConfig{
			ResendAPIKey:    "re_key",
			From:            "no-reply@example.com",
			VerificationURL: "https://app.example.com/verify",
		}, cfg.Email)
	})

	invalidValues := []struct{ name, value string }{
		{"SESSION_MAX_AGE", "abc"},
		{"MAX_SESSIONS_PER_USER", "abc"},
		{"RATE_LIMIT_REQUESTS_PER_SECOND", "abc"},
		{"RATE_LIMIT_REQUESTS_PER_SECOND", "0"},
		{"RATE_LIMIT_REQUESTS_PER_SECOND", "-1"},
		{"RATE_LIMIT_REQUESTS_PER_SECOND", "NaN"},
		{"RATE_LIMIT_REQUESTS_PER_SECOND", "Inf"},
		{"RATE_LIMIT_REQUESTS_PER_SECOND", "-Inf"},
		{"RATE_LIMIT_BURST", "abc"},
		{"RATE_LIMIT_BURST", "0"},
		{"DB_STATS_LOG_INTERVAL", "abc"},
		{"DB_STATS_LOG_INTERVAL", "0s"},
		{"DB_MAX_CONNS", "abc"},
		{"DB_MAX_CONNS", "0"},
		{"DB_MIN_CONNS", "abc"},
		{"DB_MIN_CONNS", "-1"},
		{"DB_MAX_CONN_LIFETIME", "abc"},
		{"DB_MAX_CONN_LIFETIME", "0s"},
		{"DB_MAX_CONN_IDLE_TIME", "abc"},
		{"DB_MAX_CONN_IDLE_TIME", "-1m"},
		{"DB_HEALTH_CHECK_PERIOD", "abc"},
		{"DB_HEALTH_CHECK_PERIOD", "0s"},
		{"DB_CONNECT_TIMEOUT", "abc"},
		{"DB_CONNECT_TIMEOUT", "0s"},
		{"DB_SLOW_QUERY_THRESHOLD", "500"},
		{"DB_SLOW_QUERY_THRESHOLD", "-1ms"},
	}

	for _, tc := range invalidValues {
		t.Run("error - "+tc.name+" is invalid: "+tc.value, func(t *testing.T) {
			t.Setenv("JWT_SECRET", validJWTSecret)
			t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
			t.Setenv("API_ENV", "development")
			t.Setenv(tc.name, tc.value)

			cfg, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.name)
			assert.Nil(t, cfg)
		})
	}

	emailVars := map[string]string{
		"RESEND_API_KEY":         "re_key",
		"EMAIL_FROM":             "no-reply@example.com",
		"EMAIL_VERIFICATION_URL": "https://app.example.com/verify",
	}

	for name := range emailVars {
		t.Run("returns error outside development when "+name+" is missing", func(t *testing.T) {
			t.Setenv("JWT_SECRET", validJWTSecret)
			t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
			t.Setenv("API_ENV", "production")
			t.Setenv("OAUTH_CALLBACK_ALLOW_LIST", "http://a.com/cb")
			for k, v := range emailVars {
				t.Setenv(k, v)
			}
			t.Setenv(name, "")

			cfg, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
			assert.Nil(t, cfg)
		})
	}

	t.Run("requires email vars when API_ENV is unset", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "")
		t.Setenv("RESEND_API_KEY", "")
		t.Setenv("EMAIL_FROM", "")
		t.Setenv("EMAIL_VERIFICATION_URL", "")

		cfg, err := config.Load()

		require.Error(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("defaults SESSION_MAX_AGE to 30 days", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "development")
		t.Setenv("SESSION_MAX_AGE", "")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, 30*24*time.Hour, cfg.SessionMaxAge)
	})

	t.Run("reads SESSION_MAX_AGE", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "development")
		t.Setenv("SESSION_MAX_AGE", "72h")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, 72*time.Hour, cfg.SessionMaxAge)
	})

	for _, value := range []string{"0s", "-1h"} {
		t.Run("returns error when SESSION_MAX_AGE is not positive: "+value, func(t *testing.T) {
			t.Setenv("JWT_SECRET", validJWTSecret)
			t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
			t.Setenv("API_ENV", "development")
			t.Setenv("SESSION_MAX_AGE", value)

			cfg, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "SESSION_MAX_AGE")
			assert.Nil(t, cfg)
		})
	}

	t.Run("defaults MAX_SESSIONS_PER_USER to 10", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "development")
		t.Setenv("MAX_SESSIONS_PER_USER", "")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, 10, cfg.MaxSessionsPerUser)
	})

	t.Run("reads MAX_SESSIONS_PER_USER", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "development")
		t.Setenv("MAX_SESSIONS_PER_USER", "3")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, 3, cfg.MaxSessionsPerUser)
	})

	for _, value := range []string{"0", "-1"} {
		t.Run("returns error when MAX_SESSIONS_PER_USER is not positive: "+value, func(t *testing.T) {
			t.Setenv("JWT_SECRET", validJWTSecret)
			t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
			t.Setenv("API_ENV", "development")
			t.Setenv("MAX_SESSIONS_PER_USER", value)

			cfg, err := config.Load()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "MAX_SESSIONS_PER_USER")
			assert.Nil(t, cfg)
		})
	}

	t.Run("allows missing email vars in development", func(t *testing.T) {
		t.Setenv("JWT_SECRET", validJWTSecret)
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("API_ENV", "development")
		t.Setenv("RESEND_API_KEY", "")
		t.Setenv("EMAIL_FROM", "")
		t.Setenv("EMAIL_VERIFICATION_URL", "")

		cfg, err := config.Load()

		require.NoError(t, err)
		assert.Equal(t, config.EmailConfig{}, cfg.Email)
	})
}

func TestLoadDatabaseConfig(t *testing.T) {
	t.Run("uses defaults when env vars are unset", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("DB_MAX_CONNS", "")
		t.Setenv("DB_MIN_CONNS", "")
		t.Setenv("DB_MAX_CONN_LIFETIME", "")
		t.Setenv("DB_MAX_CONN_IDLE_TIME", "")
		t.Setenv("DB_HEALTH_CHECK_PERIOD", "")
		t.Setenv("DB_CONNECT_TIMEOUT", "")
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "")

		cfg, err := config.LoadDatabaseConfig()

		require.NoError(t, err)
		assert.Equal(t, 200*time.Millisecond, cfg.SlowQueryThreshold)
		assert.Equal(t, int32(25), cfg.MaxConns)
		assert.Equal(t, int32(5), cfg.MinConns)
		assert.Equal(t, time.Hour, cfg.MaxConnLifetime)
		assert.Equal(t, 30*time.Minute, cfg.MaxConnIdleTime)
		assert.Equal(t, time.Minute, cfg.HealthCheckPeriod)
		assert.Equal(t, 15*time.Second, cfg.ConnectTimeout)
	})

	t.Run("reads values from env", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
		t.Setenv("DB_MAX_CONNS", "10")
		t.Setenv("DB_MIN_CONNS", "2")
		t.Setenv("DB_MAX_CONN_LIFETIME", "2h")
		t.Setenv("DB_MAX_CONN_IDLE_TIME", "15m")
		t.Setenv("DB_HEALTH_CHECK_PERIOD", "30s")
		t.Setenv("DB_CONNECT_TIMEOUT", "5s")
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "500ms")

		cfg, err := config.LoadDatabaseConfig()

		require.NoError(t, err)
		assert.Equal(t, 500*time.Millisecond, cfg.SlowQueryThreshold)
		assert.Equal(t, int32(10), cfg.MaxConns)
		assert.Equal(t, int32(2), cfg.MinConns)
		assert.Equal(t, 2*time.Hour, cfg.MaxConnLifetime)
		assert.Equal(t, 15*time.Minute, cfg.MaxConnIdleTime)
		assert.Equal(t, 30*time.Second, cfg.HealthCheckPeriod)
		assert.Equal(t, 5*time.Second, cfg.ConnectTimeout)
	})

	t.Run("accepts zero DB_SLOW_QUERY_THRESHOLD", func(t *testing.T) {
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")

		cfg, err := config.LoadDatabaseConfig()

		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), cfg.SlowQueryThreshold)
	})

	t.Run("error - DB_MIN_CONNS exceeds DB_MAX_CONNS", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "5")
		t.Setenv("DB_MIN_CONNS", "20")

		_, err := config.LoadDatabaseConfig()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DB_MIN_CONNS")
	})

	for _, tc := range []struct{ name, value string }{
		{"DB_MAX_CONNS", "abc"},
		{"DB_MAX_CONNS", "3000000000"},
		{"DB_MAX_CONNS", "0"},
		{"DB_CONNECT_TIMEOUT", "abc"},
		{"DB_SLOW_QUERY_THRESHOLD", "500"},
		{"DB_SLOW_QUERY_THRESHOLD", "-1ms"},
	} {
		t.Run("error - "+tc.name+" is invalid: "+tc.value, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)

			_, err := config.LoadDatabaseConfig()

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.name)
		})
	}
}
