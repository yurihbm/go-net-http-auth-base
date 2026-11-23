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

func setupPasswordResetsRepoTest(t *testing.T) (domain.PasswordResetRepository, *domain.User) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	user := seedUser(t, repositories.NewUsersPostgresRepository(testDB))
	return repositories.NewPasswordResetsPostgresRepository(testDB), user
}

func seedPasswordReset(t *testing.T, repo domain.PasswordResetRepository, user *domain.User, codeHash string) *domain.PasswordReset {
	t.Helper()
	reset, err := repo.Create(context.Background(), domain.PasswordReset{
		UUID:         uuid.Must(uuid.NewV7()).String(),
		UserUUID:     user.UUID,
		Email:        user.Email,
		EmailVersion: user.EmailVersion,
		CodeHash:     codeHash,
		ExpiresAt:    time.Now().Add(domain.PasswordResetTTL).Unix(),
	})
	require.NoError(t, err)
	return reset
}

func setPasswordResetExpiry(t *testing.T, resetUUID string, offset time.Duration) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE password_resets SET expires_at = now() + $2::interval WHERE uuid = $1",
		resetUUID, offset.String(),
	)
	require.NoError(t, err)
}

func passwordResetAttempts(t *testing.T, resetUUID string) int {
	t.Helper()
	var attempts int
	require.NoError(t, testDB.QueryRow(context.Background(), "SELECT attempts FROM password_resets WHERE uuid = $1", resetUUID).Scan(&attempts))
	return attempts
}

func countPasswordResets(t *testing.T) int {
	t.Helper()
	var count int
	require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM password_resets").Scan(&count))
	return count
}

func TestPasswordResetsPostgresRepository_Create(t *testing.T) {
	repo, user := setupPasswordResetsRepoTest(t)

	t.Run("success", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		assert.Equal(t, user.UUID, reset.UserUUID)
		assert.Equal(t, user.Email, reset.Email)
		assert.Equal(t, user.EmailVersion, reset.EmailVersion)
		assert.Equal(t, "hash", reset.CodeHash)
		assert.Equal(t, 0, reset.Attempts)
		assert.InDelta(t, time.Now().Add(domain.PasswordResetTTL).Unix(), reset.ExpiresAt, 5)
	})

	t.Run("error - unknown user", func(t *testing.T) {
		_, err := repo.Create(context.Background(), domain.PasswordReset{
			UUID:      uuid.Must(uuid.NewV7()).String(),
			UserUUID:  uuid.Must(uuid.NewV7()).String(),
			Email:     "ghost@example.com",
			CodeHash:  "hash",
			ExpiresAt: time.Now().Add(domain.PasswordResetTTL).Unix(),
		})

		assertInternalError(t, err)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		_, err := repo.Create(context.Background(), domain.PasswordReset{UUID: "invalid", UserUUID: user.UUID})

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestPasswordResetsPostgresRepository_FindByUUID(t *testing.T) {
	repo, user := setupPasswordResetsRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		found, err := repo.FindByUUID(ctx, reset.UUID)

		require.NoError(t, err)
		assert.Equal(t, reset, found)
	})

	t.Run("error - expired", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")
		setPasswordResetExpiry(t, reset.UUID, -time.Minute)

		_, err := repo.FindByUUID(ctx, reset.UUID)

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - unknown", func(t *testing.T) {
		_, err := repo.FindByUUID(ctx, uuid.Must(uuid.NewV7()).String())

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		_, err := repo.FindByUUID(ctx, "not-a-uuid")

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - canceled context", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		_, err := repo.FindByUUID(canceledContext(), reset.UUID)

		assertInternalError(t, err)
	})
}

func TestPasswordResetsPostgresRepository_Attempt(t *testing.T) {
	repo, user := setupPasswordResetsRepoTest(t)
	ctx := context.Background()

	t.Run("success counts attempts up to the limit", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		for i := 1; i <= domain.PasswordResetMaxAttempts; i++ {
			attempted, err := repo.Attempt(ctx, reset.UUID, domain.PasswordResetMaxAttempts)
			require.NoError(t, err)
			assert.Equal(t, i, passwordResetAttempts(t, reset.UUID))
			assert.Equal(t, "hash", attempted.CodeHash)
		}

		_, err := repo.Attempt(ctx, reset.UUID, domain.PasswordResetMaxAttempts)
		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - expired", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")
		setPasswordResetExpiry(t, reset.UUID, -time.Second)

		_, err := repo.Attempt(ctx, reset.UUID, domain.PasswordResetMaxAttempts)

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		_, err := repo.Attempt(ctx, "not-a-uuid", domain.PasswordResetMaxAttempts)

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})
}

func TestPasswordResetsPostgresRepository_Consume(t *testing.T) {
	repo, user := setupPasswordResetsRepoTest(t)
	ctx := context.Background()

	t.Run("error - wrong hash keeps the reset", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		_, err := repo.Consume(ctx, reset.UUID, "other-hash")

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		_, err = repo.FindByUUID(ctx, reset.UUID)
		assert.NoError(t, err)
	})

	t.Run("success is single use", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		consumed, err := repo.Consume(ctx, reset.UUID, "hash")
		require.NoError(t, err)
		assert.Equal(t, reset.UUID, consumed.UUID)
		assert.Equal(t, user.UUID, consumed.UserUUID)

		_, err = repo.Consume(ctx, reset.UUID, "hash")
		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - expired", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")
		setPasswordResetExpiry(t, reset.UUID, -time.Second)

		_, err := repo.Consume(ctx, reset.UUID, "hash")

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - canceled context", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		_, err := repo.Consume(canceledContext(), reset.UUID, "hash")

		assertInternalError(t, err)
	})
}

func TestPasswordResetsPostgresRepository_Delete(t *testing.T) {
	repo, user := setupPasswordResetsRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		reset := seedPasswordReset(t, repo, user, "hash")

		require.NoError(t, repo.Delete(ctx, reset.UUID))

		assert.Equal(t, 0, countPasswordResets(t))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		assert.ErrorIs(t, repo.Delete(ctx, "not-a-uuid"), domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - canceled context", func(t *testing.T) {
		assertInternalError(t, repo.Delete(canceledContext(), uuid.Must(uuid.NewV7()).String()))
	})
}

func TestPasswordResetsPostgresRepository_DeleteByUser(t *testing.T) {
	repo, user := setupPasswordResetsRepoTest(t)
	ctx := context.Background()

	t.Run("success deletes only the resets of the user", func(t *testing.T) {
		other, err := repositories.NewUsersPostgresRepository(testDB).Create(ctx, domain.User{Name: "Other", Email: "other@example.com", PasswordHash: "hash"})
		require.NoError(t, err)
		seedPasswordReset(t, repo, user, "hash-a")
		seedPasswordReset(t, repo, user, "hash-b")
		kept := seedPasswordReset(t, repo, other, "hash-c")

		require.NoError(t, repo.DeleteByUser(ctx, user.UUID))

		assert.Equal(t, 1, countPasswordResets(t))
		_, err = repo.FindByUUID(ctx, kept.UUID)
		assert.NoError(t, err)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.DeleteByUser(ctx, "invalid")

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})

	t.Run("error - canceled context", func(t *testing.T) {
		assertInternalError(t, repo.DeleteByUser(canceledContext(), user.UUID))
	})
}
