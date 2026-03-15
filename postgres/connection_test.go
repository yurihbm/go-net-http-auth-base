package postgres_test

import (
	"context"
	"testing"
	"time"

	"go-net-http-auth-base/postgres"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPoolConfig(t *testing.T) {
	t.Run("uses defaults when env vars are unset", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "")
		t.Setenv("DB_MIN_CONNS", "")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, int32(25), cfg.MaxConns)
		assert.Equal(t, int32(5), cfg.MinConns)
	})

	t.Run("reads conn counts from env", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "10")
		t.Setenv("DB_MIN_CONNS", "2")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, int32(10), cfg.MaxConns)
		assert.Equal(t, int32(2), cfg.MinConns)
	})

	t.Run("falls back to defaults on invalid conn count env values", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "not-a-number")
		t.Setenv("DB_MIN_CONNS", "also-not-a-number")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, int32(25), cfg.MaxConns)
		assert.Equal(t, int32(5), cfg.MinConns)
	})

	t.Run("accepts large conn count values", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "100")
		t.Setenv("DB_MIN_CONNS", "10")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, int32(100), cfg.MaxConns)
		assert.Equal(t, int32(10), cfg.MinConns)
	})

	t.Run("accepts zero conn count values", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "0")
		t.Setenv("DB_MIN_CONNS", "0")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, int32(0), cfg.MaxConns)
		assert.Equal(t, int32(0), cfg.MinConns)
	})

	t.Run("caps MinConns to MaxConns when MinConns exceeds it", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "5")
		t.Setenv("DB_MIN_CONNS", "20")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, int32(5), cfg.MaxConns)
		assert.Equal(t, int32(5), cfg.MinConns)
	})

	t.Run("uses default lifetime durations when env vars are unset", func(t *testing.T) {
		t.Setenv("DB_MAX_CONN_LIFETIME", "")
		t.Setenv("DB_MAX_CONN_IDLE_TIME", "")
		t.Setenv("DB_HEALTH_CHECK_PERIOD", "")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, time.Hour, cfg.MaxConnLifetime)
		assert.Equal(t, 30*time.Minute, cfg.MaxConnIdleTime)
		assert.Equal(t, time.Minute, cfg.HealthCheckPeriod)
	})

	t.Run("reads lifetime durations from env", func(t *testing.T) {
		t.Setenv("DB_MAX_CONN_LIFETIME", "2h")
		t.Setenv("DB_MAX_CONN_IDLE_TIME", "15m")
		t.Setenv("DB_HEALTH_CHECK_PERIOD", "30s")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, 2*time.Hour, cfg.MaxConnLifetime)
		assert.Equal(t, 15*time.Minute, cfg.MaxConnIdleTime)
		assert.Equal(t, 30*time.Second, cfg.HealthCheckPeriod)
	})

	t.Run("falls back to defaults on invalid lifetime duration env values", func(t *testing.T) {
		t.Setenv("DB_MAX_CONN_LIFETIME", "not-a-duration")
		t.Setenv("DB_MAX_CONN_IDLE_TIME", "also-invalid")
		t.Setenv("DB_HEALTH_CHECK_PERIOD", "??")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, time.Hour, cfg.MaxConnLifetime)
		assert.Equal(t, 30*time.Minute, cfg.MaxConnIdleTime)
		assert.Equal(t, time.Minute, cfg.HealthCheckPeriod)
	})

	t.Run("uses default connect timeout when env is unset", func(t *testing.T) {
		t.Setenv("DB_CONNECT_TIMEOUT", "")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, 15*time.Second, cfg.ConnectTimeout)
	})

	t.Run("reads connect timeout from env", func(t *testing.T) {
		t.Setenv("DB_CONNECT_TIMEOUT", "5s")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, 5*time.Second, cfg.ConnectTimeout)
	})

	t.Run("falls back to default connect timeout on invalid env value", func(t *testing.T) {
		t.Setenv("DB_CONNECT_TIMEOUT", "not-a-duration")

		cfg := postgres.NewPoolConfig()

		assert.Equal(t, 15*time.Second, cfg.ConnectTimeout)
	})
}

func TestNewConnectionPool(t *testing.T) {
	t.Run("returns error when DATABASE_URL is missing", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")

		_, err := postgres.NewConnectionPool(context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DATABASE_URL")
	})

	t.Run("returns error on invalid DATABASE_URL", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "not-a-valid-url")

		_, err := postgres.NewConnectionPool(context.Background())

		require.Error(t, err)
	})

	t.Run("returns error when ping times out", func(t *testing.T) {
		// Use a reachable host on a closed port to force a fast connect refusal.
		// The context deadline ensures the test does not hang.
		t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:19999/db?sslmode=disable")

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := postgres.NewConnectionPool(ctx)

		require.Error(t, err)
	})
}
