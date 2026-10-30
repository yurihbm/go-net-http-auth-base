package postgres_test

import (
	"context"
	"testing"
	"time"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/multitracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConnectionPool(t *testing.T) {
	t.Run("returns error when DATABASE_URL is missing", func(t *testing.T) {
		_, err := postgres.NewConnectionPool(context.Background(), config.DatabaseConfig{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DATABASE_URL")
	})

	t.Run("returns error on invalid DATABASE_URL", func(t *testing.T) {
		_, err := postgres.NewConnectionPool(context.Background(), config.DatabaseConfig{
			URL: "not-a-valid-url",
		})

		require.Error(t, err)
	})

	t.Run("returns error when ping times out", func(t *testing.T) {
		// Use a reachable host on a closed port to force a fast connect refusal.
		// ConnectTimeout is set to a short value so the pgx handshake timeout
		// fires quickly on both TCP RST (REJECT) and DROP network configurations.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := postgres.NewConnectionPool(ctx, config.DatabaseConfig{
			URL:            "postgres://user:pass@localhost:19999/db?sslmode=disable",
			ConnectTimeout: 500 * time.Millisecond,
		})

		require.Error(t, err)
	})

	t.Run("no extras - slow query tracer only", func(t *testing.T) {
		cfg, err := postgres.NewPoolConfig(config.DatabaseConfig{
			URL: "postgres://user:pass@localhost:19999/db?sslmode=disable",
		})

		require.NoError(t, err)
		assert.IsType(t, &postgres.SlowQueryTracer{}, cfg.ConnConfig.Tracer)
	})

	t.Run("composes extra tracers with slow query tracer", func(t *testing.T) {
		extra := postgres.NewSlowQueryTracer(time.Second)

		cfg, err := postgres.NewPoolConfig(config.DatabaseConfig{
			URL: "postgres://user:pass@localhost:19999/db?sslmode=disable",
		}, extra)

		require.NoError(t, err)
		multi, ok := cfg.ConnConfig.Tracer.(*multitracer.Tracer)
		require.True(t, ok)
		require.Len(t, multi.QueryTracers, 2)
		assert.IsType(t, &postgres.SlowQueryTracer{}, multi.QueryTracers[0])
		assert.Same(t, extra, multi.QueryTracers[1])
	})
}
