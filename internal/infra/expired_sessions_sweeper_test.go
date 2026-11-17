package infra_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/infra"
)

func TestExpiredSessionsSweeper_RunMaintenance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	sweeper := infra.NewExpiredSessionsSweeper(testDB)

	reset := func(t *testing.T) string {
		t.Helper()
		_, err := testDB.Exec(ctx, "TRUNCATE TABLE step_up_challenges, user_sessions, users RESTART IDENTITY CASCADE")
		require.NoError(t, err)
		var userUUID string
		err = testDB.QueryRow(ctx,
			"INSERT INTO users (name, email) VALUES ('Sweep', 'sweep@example.com') RETURNING uuid::text",
		).Scan(&userUUID)
		require.NoError(t, err)
		return userUUID
	}

	insertSession := func(t *testing.T, userUUID string, expiresIn, lastUsedAgo time.Duration) string {
		t.Helper()
		var sessionUUID string
		err := testDB.QueryRow(ctx,
			`INSERT INTO user_sessions (user_uuid, current_jti, expires_at, last_used_at)
			VALUES ($1, 'jti', now() + $2::interval, now() - $3::interval) RETURNING uuid::text`,
			userUUID, expiresIn.String(), lastUsedAgo.String(),
		).Scan(&sessionUUID)
		require.NoError(t, err)
		return sessionUUID
	}

	insertChallenge := func(t *testing.T, userUUID, sessionUUID string, expiresIn time.Duration) {
		t.Helper()
		_, err := testDB.Exec(ctx,
			`INSERT INTO step_up_challenges (user_uuid, session_uuid, code_hash, expires_at)
			VALUES ($1, $2, 'hash', now() + $3::interval)`,
			userUUID, sessionUUID, expiresIn.String(),
		)
		require.NoError(t, err)
	}

	count := func(t *testing.T, table string) int {
		t.Helper()
		var n int
		require.NoError(t, testDB.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n))
		return n
	}

	t.Run("deletes expired session", func(t *testing.T) {
		userUUID := reset(t)
		insertSession(t, userUUID, -time.Minute, 0)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 0, count(t, "user_sessions"))
	})

	t.Run("deletes idle session", func(t *testing.T) {
		userUUID := reset(t)
		insertSession(t, userUUID, time.Hour, domain.TokenExpirationRefresh+time.Minute)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 0, count(t, "user_sessions"))
	})

	t.Run("keeps live session", func(t *testing.T) {
		userUUID := reset(t)
		insertSession(t, userUUID, time.Hour, time.Minute)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 1, count(t, "user_sessions"))
	})

	t.Run("deletes expired challenge and keeps live one", func(t *testing.T) {
		userUUID := reset(t)
		expiredChallengeSession := insertSession(t, userUUID, time.Hour, 0)
		liveChallengeSession := insertSession(t, userUUID, time.Hour, 0)
		insertChallenge(t, userUUID, expiredChallengeSession, -time.Minute)
		insertChallenge(t, userUUID, liveChallengeSession, time.Minute)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 2, count(t, "user_sessions"))
		assert.Equal(t, 1, count(t, "step_up_challenges"))
		var sessionUUID string
		require.NoError(t, testDB.QueryRow(ctx, "SELECT session_uuid::text FROM step_up_challenges").Scan(&sessionUUID))
		assert.Equal(t, liveChallengeSession, sessionUUID)
	})

	t.Run("deletes more rows than one batch", func(t *testing.T) {
		userUUID := reset(t)
		for range 7 {
			sessionUUID := insertSession(t, userUUID, -time.Minute, 0)
			insertChallenge(t, userUUID, sessionUUID, -time.Minute)
		}
		keptSession := insertSession(t, userUUID, time.Hour, 0)
		insertChallenge(t, userUUID, keptSession, time.Hour)
		for range 7 {
			sessionUUID := insertSession(t, userUUID, time.Hour, 0)
			insertChallenge(t, userUUID, sessionUUID, -time.Minute)
		}

		require.NoError(t, sweeper.RunMaintenanceWithBatchSize(ctx, 3))

		assert.Equal(t, 8, count(t, "user_sessions"))
		assert.Equal(t, 1, count(t, "step_up_challenges"))
	})
}
