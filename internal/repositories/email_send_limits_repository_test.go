package repositories_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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
		require.NoError(t, limiter.ReserveCodeGuess(context.Background(), limitedEmail, domain.EmailCodeFailureWindow))

		assert.NoError(t, reserveSend(limiter))
	})

	t.Run("error - canceled context", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		assertInternalError(t, limiter.ReserveSend(canceledContext(), limitedEmail, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow))
	})
}

func codeFailures(t *testing.T) int {
	t.Helper()
	var failures int
	require.NoError(t, testDB.QueryRow(context.Background(), "SELECT failures FROM email_send_limits WHERE email = $1", limitedEmail).Scan(&failures))
	return failures
}

func TestEmailSendLimitsPostgresRepository_ReserveCodeGuess(t *testing.T) {
	ctx := context.Background()

	t.Run("success counts guesses up to the cap, then locks", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)

		for range domain.EmailMaxCodeFailures {
			require.NoError(t, limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow))
		}

		assert.Equal(t, domain.ErrEmailCodeLocked, limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow))
		assert.Equal(t, domain.EmailMaxCodeFailures, codeFailures(t))
	})

	t.Run("success window restarts after it ends", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		for range domain.EmailMaxCodeFailures {
			require.NoError(t, limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow))
		}

		shiftEmailSendLimit(t, "failures_window_start", -domain.EmailCodeFailureWindow)

		require.NoError(t, limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow))
		assert.Equal(t, 1, codeFailures(t))
	})

	t.Run("success concurrent guesses never exceed the cap", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		var granted, locked atomic.Int32

		var wg sync.WaitGroup
		for range 30 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				switch err := limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow); {
				case err == nil:
					granted.Add(1)
				case errors.Is(err, domain.ErrEmailCodeLocked):
					locked.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		wg.Wait()

		assert.Equal(t, int32(domain.EmailMaxCodeFailures), granted.Load())
		assert.Equal(t, int32(30-domain.EmailMaxCodeFailures), locked.Load())
		assert.Equal(t, domain.EmailMaxCodeFailures, codeFailures(t))
	})

	t.Run("error - canceled context", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		assertInternalError(t, limiter.ReserveCodeGuess(canceledContext(), limitedEmail, domain.EmailCodeFailureWindow))
	})
}

func TestEmailSendLimitsPostgresRepository_RefundCodeGuess(t *testing.T) {
	ctx := context.Background()

	t.Run("success gives one guess back", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		for range 3 {
			require.NoError(t, limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow))
		}

		require.NoError(t, limiter.RefundCodeGuess(ctx, limitedEmail))

		assert.Equal(t, 2, codeFailures(t))
	})

	t.Run("success never goes below zero", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		require.NoError(t, limiter.ReserveCodeGuess(ctx, limitedEmail, domain.EmailCodeFailureWindow))

		require.NoError(t, limiter.RefundCodeGuess(ctx, limitedEmail))
		require.NoError(t, limiter.RefundCodeGuess(ctx, limitedEmail))

		assert.Equal(t, 0, codeFailures(t))
	})

	t.Run("success unknown address is a no-op", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)

		assert.NoError(t, limiter.RefundCodeGuess(ctx, limitedEmail))
	})

	t.Run("error - canceled context", func(t *testing.T) {
		limiter := setupEmailSendLimitsRepoTest(t)
		assertInternalError(t, limiter.RefundCodeGuess(canceledContext(), limitedEmail))
	})
}
