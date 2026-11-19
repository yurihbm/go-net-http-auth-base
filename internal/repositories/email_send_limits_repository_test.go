package repositories_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const limitedEmail = "limited@example.com"

func setupEmailSendLimitsRepoTest(t *testing.T) domain.EmailSendLimiter {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	return repositories.NewEmailSendLimitsPostgresRepository(testDB)
}

func shiftEmailSendLimit(t *testing.T, column string, offset time.Duration) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE email_send_limits SET "+column+" = "+column+" + $2::interval WHERE email = $1",
		limitedEmail, offset.String(),
	)
	require.NoError(t, err)
}

func reserveSend(limiter domain.EmailSendLimiter) error {
	return limiter.ReserveSend(context.Background(), limitedEmail, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow)
}

func assertSendLimit(t *testing.T, err error) {
	t.Helper()
	var tooManyErr *domain.TooManyRequestsError
	require.True(t, errors.As(err, &tooManyErr), "expected TooManyRequestsError, got %v", err)
	assert.Equal(t, "auth.email.sendLimit", err.Error())
}

func TestEmailSendLimitsPostgresRepository_ReserveSend(t *testing.T) {
	t.Run("error - cooldown after a send", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)

		require.NoError(t, reserveSend(limiter))

		assertSendLimit(t, reserveSend(limiter))
	})

	t.Run("error - hourly cap, then the window restarts", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)

		for range domain.EmailMaxSendsPerWindow {
			require.NoError(t, reserveSend(limiter))
			shiftEmailSendLimit(t, "last_sent_at", -2*domain.EmailSendCooldown)
		}
		assertSendLimit(t, reserveSend(limiter))

		shiftEmailSendLimit(t, "window_start", -domain.EmailSendWindow)
		require.NoError(t, reserveSend(limiter))
		var sends int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT sends FROM email_send_limits WHERE email = $1", limitedEmail).Scan(&sends))
		assert.Equal(t, 1, sends)
	})

	t.Run("success after a recorded failure", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		_, err := limiter.RecordCodeFailure(context.Background(), limitedEmail, domain.EmailCodeFailureWindow)
		require.NoError(t, err)

		assert.NoError(t, reserveSend(limiter))
	})
}

func TestEmailSendLimitsPostgresRepository_RecordCodeFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("success counts failures and restarts after the window", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		require.NoError(t, reserveSend(limiter))

		for i := 1; i <= 3; i++ {
			failures, err := limiter.RecordCodeFailure(ctx, limitedEmail, domain.EmailCodeFailureWindow)
			require.NoError(t, err)
			assert.Equal(t, i, failures)
		}

		shiftEmailSendLimit(t, "failures_window_start", -domain.EmailCodeFailureWindow)
		failures, err := limiter.RecordCodeFailure(ctx, limitedEmail, domain.EmailCodeFailureWindow)
		require.NoError(t, err)
		assert.Equal(t, 1, failures)
	})
}

func TestEmailSendLimitsPostgresRepository_CodeFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("success zero for an unknown address", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)

		failures, err := limiter.CodeFailures(ctx, limitedEmail, domain.EmailCodeFailureWindow)

		require.NoError(t, err)
		assert.Equal(t, 0, failures)
	})

	t.Run("success counts failures inside the window only", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		for range 2 {
			_, err := limiter.RecordCodeFailure(ctx, limitedEmail, domain.EmailCodeFailureWindow)
			require.NoError(t, err)
		}

		failures, err := limiter.CodeFailures(ctx, limitedEmail, domain.EmailCodeFailureWindow)
		require.NoError(t, err)
		assert.Equal(t, 2, failures)

		shiftEmailSendLimit(t, "failures_window_start", -domain.EmailCodeFailureWindow)
		failures, err = limiter.CodeFailures(ctx, limitedEmail, domain.EmailCodeFailureWindow)
		require.NoError(t, err)
		assert.Equal(t, 0, failures)
	})
}
