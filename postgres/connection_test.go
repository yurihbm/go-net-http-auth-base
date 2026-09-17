package postgres_test

import (
	"context"
	"testing"
	"time"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/postgres"

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
}
