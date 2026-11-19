package repositories_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPendingSignupsRepoTest(t *testing.T) domain.PendingSignupRepository {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	return repositories.NewPendingSignupsPostgresRepository(testDB)
}

func seedPendingSignup(t *testing.T, repo domain.PendingSignupRepository, codeHash string) *domain.PendingSignup {
	t.Helper()
	now := time.Now()
	pending, err := repo.Create(context.Background(), domain.PendingSignup{
		UUID:          uuid.NewString(),
		Kind:          domain.PendingSignupKindCredentials,
		Name:          "Pending User",
		Email:         "pending@example.com",
		PasswordHash:  "bcrypt-hash",
		CodeHash:      codeHash,
		CodeExpiresAt: now.Add(domain.SignupCodeTTL).Unix(),
		ExpiresAt:     now.Add(domain.PendingSignupTTL).Unix(),
	})
	require.NoError(t, err)
	return pending
}

func setPendingSignupTimes(t *testing.T, pendingUUID string, column string, offset time.Duration) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE pending_signups SET "+column+" = now() + $2::interval WHERE uuid = $1",
		pendingUUID, offset.String(),
	)
	require.NoError(t, err)
}

func assertNoPending(t *testing.T, err error) {
	t.Helper()
	var unauthorizedErr *domain.UnauthorizedError
	require.True(t, errors.As(err, &unauthorizedErr), "expected UnauthorizedError, got %v", err)
	assert.Equal(t, "auth.signup.noPending", err.Error())
}

func TestPendingSignupsPostgresRepository_Create(t *testing.T) {
	repo := setupPendingSignupsRepoTest(t)
	ctx := context.Background()

	t.Run("success credentials", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash-1")

		assert.Equal(t, domain.PendingSignupKindCredentials, pending.Kind)
		assert.Equal(t, "pending@example.com", pending.Email)
		assert.Equal(t, "bcrypt-hash", pending.PasswordHash)
		assert.Equal(t, "hash-1", pending.CodeHash)
		assert.Equal(t, 0, pending.Attempts)
		assert.InDelta(t, time.Now().Add(domain.SignupCodeTTL).Unix(), pending.CodeExpiresAt, 5)
		assert.InDelta(t, time.Now().Add(domain.PendingSignupTTL).Unix(), pending.ExpiresAt, 5)
	})

	t.Run("success oauth", func(t *testing.T) {
		pending, err := repo.Create(ctx, domain.PendingSignup{
			UUID:           uuid.NewString(),
			Kind:           domain.PendingSignupKindOAuth,
			Name:           "OAuth User",
			Email:          "pending@example.com",
			Provider:       domain.OAuthProviderGitHub,
			ProviderUserID: "gh-1",
			CodeHash:       "hash",
			CodeExpiresAt:  time.Now().Add(domain.SignupCodeTTL).Unix(),
			ExpiresAt:      time.Now().Add(domain.PendingSignupTTL).Unix(),
		})

		require.NoError(t, err)
		assert.Equal(t, domain.OAuthProviderGitHub, pending.Provider)
		assert.Equal(t, "gh-1", pending.ProviderUserID)
		assert.Empty(t, pending.PasswordHash)
	})

	t.Run("success several pending signups for the same email", func(t *testing.T) {
		seedPendingSignup(t, repo, "hash-a")
		seedPendingSignup(t, repo, "hash-b")
	})

	t.Run("error - credentials without password hash", func(t *testing.T) {
		_, err := repo.Create(ctx, domain.PendingSignup{
			UUID:          uuid.NewString(),
			Kind:          domain.PendingSignupKindCredentials,
			Name:          "Broken",
			Email:         "broken@example.com",
			CodeHash:      "hash",
			CodeExpiresAt: time.Now().Add(domain.SignupCodeTTL).Unix(),
			ExpiresAt:     time.Now().Add(domain.PendingSignupTTL).Unix(),
		})

		var internalErr *domain.InternalServerError
		assert.True(t, errors.As(err, &internalErr))
	})
}

func TestPendingSignupsPostgresRepository_FindByUUID(t *testing.T) {
	repo := setupPendingSignupsRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")

		found, err := repo.FindByUUID(ctx, pending.UUID)

		require.NoError(t, err)
		assert.Equal(t, pending, found)
	})

	t.Run("error - expired", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")
		setPendingSignupTimes(t, pending.UUID, "expires_at", -time.Minute)

		_, err := repo.FindByUUID(ctx, pending.UUID)

		assertNoPending(t, err)
	})

	t.Run("error - unknown", func(t *testing.T) {
		_, err := repo.FindByUUID(ctx, uuid.NewString())

		assertNoPending(t, err)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		_, err := repo.FindByUUID(ctx, "not-a-uuid")

		assertNoPending(t, err)
	})
}

func TestPendingSignupsPostgresRepository_Attempt(t *testing.T) {
	repo := setupPendingSignupsRepoTest(t)
	ctx := context.Background()

	t.Run("success counts attempts up to the limit", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")

		for i := 1; i <= domain.SignupMaxAttempts; i++ {
			attempted, err := repo.Attempt(ctx, pending.UUID, domain.SignupMaxAttempts)
			require.NoError(t, err)
			assert.Equal(t, i, attempted.Attempts)
			assert.Equal(t, "hash", attempted.CodeHash)
		}

		_, err := repo.Attempt(ctx, pending.UUID, domain.SignupMaxAttempts)
		assertNoPending(t, err)
	})

	t.Run("error - code expired", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")
		setPendingSignupTimes(t, pending.UUID, "code_expires_at", -time.Second)

		_, err := repo.Attempt(ctx, pending.UUID, domain.SignupMaxAttempts)

		assertNoPending(t, err)
	})

	t.Run("error - pending signup expired", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")
		setPendingSignupTimes(t, pending.UUID, "expires_at", -time.Second)

		_, err := repo.Attempt(ctx, pending.UUID, domain.SignupMaxAttempts)

		assertNoPending(t, err)
	})
}

func TestPendingSignupsPostgresRepository_Consume(t *testing.T) {
	repo := setupPendingSignupsRepoTest(t)
	ctx := context.Background()

	t.Run("error - wrong hash keeps the pending signup", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")

		_, err := repo.Consume(ctx, pending.UUID, "other-hash")

		assertNoPending(t, err)
		_, err = repo.FindByUUID(ctx, pending.UUID)
		assert.NoError(t, err)
	})

	t.Run("success is single use", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")

		consumed, err := repo.Consume(ctx, pending.UUID, "hash")
		require.NoError(t, err)
		assert.Equal(t, pending.UUID, consumed.UUID)
		assert.Equal(t, "bcrypt-hash", consumed.PasswordHash)

		_, err = repo.Consume(ctx, pending.UUID, "hash")
		assertNoPending(t, err)
		_, err = repo.FindByUUID(ctx, pending.UUID)
		assertNoPending(t, err)
	})
}

func TestPendingSignupsPostgresRepository_Resend(t *testing.T) {
	repo := setupPendingSignupsRepoTest(t)
	ctx := context.Background()

	t.Run("error - expired pending signup", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")
		setPendingSignupTimes(t, pending.UUID, "expires_at", -time.Minute)

		_, err := repo.Resend(ctx, pending.UUID, "new-hash", domain.SignupCodeTTL)

		assertNoPending(t, err)
	})

	t.Run("success replaces the code and resets attempts", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")
		_, err := repo.Attempt(ctx, pending.UUID, domain.SignupMaxAttempts)
		require.NoError(t, err)

		resent, err := repo.Resend(ctx, pending.UUID, "new-hash", domain.SignupCodeTTL)

		require.NoError(t, err)
		assert.Equal(t, "new-hash", resent.CodeHash)
		assert.Equal(t, 0, resent.Attempts)
		assert.InDelta(t, time.Now().Add(domain.SignupCodeTTL).Unix(), resent.CodeExpiresAt, 5)
		assert.Equal(t, pending.ExpiresAt, resent.ExpiresAt)
	})

	t.Run("success never extends the code past the pending signup", func(t *testing.T) {
		pending := seedPendingSignup(t, repo, "hash")
		setPendingSignupTimes(t, pending.UUID, "expires_at", 2*time.Minute)

		resent, err := repo.Resend(ctx, pending.UUID, "new-hash", domain.SignupCodeTTL)

		require.NoError(t, err)
		assert.Equal(t, resent.ExpiresAt, resent.CodeExpiresAt)
	})
}

func TestPendingSignupsPostgresRepository_Delete(t *testing.T) {
	repo := setupPendingSignupsRepoTest(t)
	ctx := context.Background()

	pending := seedPendingSignup(t, repo, "hash")

	require.NoError(t, repo.Delete(ctx, pending.UUID))

	_, err := repo.FindByUUID(ctx, pending.UUID)
	assertNoPending(t, err)
}
