package infra_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/infra"
)

func TestExpiredRecordsSweeper_RunMaintenance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	sweeper := infra.NewExpiredRecordsSweeper(testDB)

	reset := func(t *testing.T) string {
		t.Helper()
		_, err := testDB.Exec(ctx, "TRUNCATE TABLE email_send_limits, pending_signups, session_challenges, user_sessions, users RESTART IDENTITY CASCADE")
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
			`INSERT INTO session_challenges (user_uuid, session_uuid, purpose, code_hash, expires_at)
			VALUES ($1, $2, 'step_up', 'hash', now() + $3::interval)`,
			userUUID, sessionUUID, expiresIn.String(),
		)
		require.NoError(t, err)
	}

	insertEmailChangeChallenge := func(t *testing.T, userUUID, sessionUUID string, expiresIn time.Duration) {
		t.Helper()
		_, err := testDB.Exec(ctx,
			`INSERT INTO session_challenges (user_uuid, session_uuid, purpose, new_email, email_version, code_hash, expires_at)
			VALUES ($1, $2, 'email_change', 'new@example.com', 0, 'hash', now() + $3::interval)`,
			userUUID, sessionUUID, expiresIn.String(),
		)
		require.NoError(t, err)
	}

	insertPendingSignup := func(t *testing.T, expiresIn time.Duration) string {
		t.Helper()
		var pendingUUID string
		err := testDB.QueryRow(ctx,
			`INSERT INTO pending_signups (kind, name, email, password_hash, code_hash, code_expires_at, expires_at)
			VALUES ('credentials', 'Pending', 'pending@example.com', 'hash', 'code', now(), now() + $1::interval) RETURNING uuid::text`,
			expiresIn.String(),
		).Scan(&pendingUUID)
		require.NoError(t, err)
		return pendingUUID
	}

	insertEmailSendLimit := func(t *testing.T, email string, windowAgo time.Duration, failuresWindowAgo *time.Duration) {
		t.Helper()
		var failuresWindowStart any
		if failuresWindowAgo != nil {
			failuresWindowStart = failuresWindowAgo.String()
		}
		_, err := testDB.Exec(ctx,
			`INSERT INTO email_send_limits (email, window_start, sends, last_sent_at, failures, failures_window_start)
			VALUES ($1, now() - $2::interval, 1, now() - $2::interval, 1, now() - $3::interval)`,
			email, windowAgo.String(), failuresWindowStart,
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

	t.Run("deletes expired challenges of every purpose and keeps live ones", func(t *testing.T) {
		userUUID := reset(t)
		expiredSession := insertSession(t, userUUID, time.Hour, 0)
		liveSession := insertSession(t, userUUID, time.Hour, 0)
		insertChallenge(t, userUUID, expiredSession, -time.Minute)
		insertEmailChangeChallenge(t, userUUID, expiredSession, -time.Minute)
		insertChallenge(t, userUUID, liveSession, time.Minute)
		insertEmailChangeChallenge(t, userUUID, liveSession, time.Minute)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 2, count(t, "user_sessions"))
		assert.Equal(t, 2, count(t, "session_challenges"))
		var stale int
		require.NoError(t, testDB.QueryRow(ctx, "SELECT count(*) FROM session_challenges WHERE session_uuid <> $1", liveSession).Scan(&stale))
		assert.Equal(t, 0, stale)
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
		assert.Equal(t, 1, count(t, "session_challenges"))
	})

	t.Run("deletes expired pending signups and keeps live ones", func(t *testing.T) {
		reset(t)
		insertPendingSignup(t, -time.Minute)
		live := insertPendingSignup(t, time.Hour)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 1, count(t, "pending_signups"))
		var pendingUUID string
		require.NoError(t, testDB.QueryRow(ctx, "SELECT uuid::text FROM pending_signups").Scan(&pendingUUID))
		assert.Equal(t, live, pendingUUID)
	})

	t.Run("deletes email send limits only when both windows expired", func(t *testing.T) {
		reset(t)
		stale := domain.EmailCodeFailureWindow + time.Minute
		recent := time.Minute
		insertEmailSendLimit(t, "stale@example.com", domain.EmailSendWindow+time.Minute, &stale)
		insertEmailSendLimit(t, "no-failures@example.com", domain.EmailSendWindow+time.Minute, nil)
		insertEmailSendLimit(t, "recent-send@example.com", time.Minute, &stale)
		insertEmailSendLimit(t, "recent-failure@example.com", domain.EmailSendWindow+time.Minute, &recent)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		rows, err := testDB.Query(ctx, "SELECT email FROM email_send_limits ORDER BY email")
		require.NoError(t, err)
		var kept []string
		for rows.Next() {
			var email string
			require.NoError(t, rows.Scan(&email))
			kept = append(kept, email)
		}
		require.NoError(t, rows.Err())
		assert.Equal(t, []string{"recent-failure@example.com", "recent-send@example.com"}, kept)
	})

	t.Run("deletes more pending signups and send limits than one batch", func(t *testing.T) {
		reset(t)
		for range 7 {
			insertPendingSignup(t, -time.Minute)
		}
		for i := range 7 {
			insertEmailSendLimit(t, fmt.Sprintf("stale-%d@example.com", i), domain.EmailSendWindow+time.Minute, nil)
		}

		require.NoError(t, sweeper.RunMaintenanceWithBatchSize(ctx, 3))

		assert.Equal(t, 0, count(t, "pending_signups"))
		assert.Equal(t, 0, count(t, "email_send_limits"))
	})

	t.Run("skips when another instance holds the lock", func(t *testing.T) {
		userUUID := reset(t)
		insertSession(t, userUUID, -time.Minute, 0)
		insertPendingSignup(t, -time.Minute)

		holder, err := testDB.Acquire(ctx)
		require.NoError(t, err)
		_, err = holder.Exec(ctx, "SELECT pg_advisory_lock($1)", infra.ExpiredRecordsSweepLockID)
		require.NoError(t, err)

		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 1, count(t, "user_sessions"))
		assert.Equal(t, 1, count(t, "pending_signups"))

		_, err = holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", infra.ExpiredRecordsSweepLockID)
		require.NoError(t, err)
		holder.Release()
		require.NoError(t, sweeper.RunMaintenance(ctx))

		assert.Equal(t, 0, count(t, "user_sessions"))
		assert.Equal(t, 0, count(t, "pending_signups"))
	})

	t.Run("completes with a single-connection pool", func(t *testing.T) {
		userUUID := reset(t)
		insertSession(t, userUUID, -time.Minute, 0)
		insertPendingSignup(t, -time.Minute)

		cfg := testDB.Config().Copy()
		cfg.MaxConns = 1
		small, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err)
		defer small.Close()

		timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		require.NoError(t, infra.NewExpiredRecordsSweeper(small).RunMaintenance(timeout))

		assert.Equal(t, 0, count(t, "user_sessions"))
		assert.Equal(t, 0, count(t, "pending_signups"))
	})

	t.Run("error - canceled context", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		assert.Error(t, sweeper.RunMaintenance(canceled))
	})
}
