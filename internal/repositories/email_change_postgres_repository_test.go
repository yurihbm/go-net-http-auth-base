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

func setupEmailChangeRepoTest(t *testing.T) (domain.EmailChangeRepository, *domain.User, *domain.UserSession) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	user := seedUser(t, repositories.NewUsersPostgresRepository(testDB))
	session := seedSession(t, repositories.NewSessionsPostgresRepository(testDB), user.UUID, "jti-1")

	return repositories.NewEmailChangePostgresRepository(testDB), user, session
}

func newEmailChangeChallenge(user *domain.User, session *domain.UserSession, hash string) domain.EmailChangeChallenge {
	return domain.EmailChangeChallenge{
		UserUUID:     user.UUID,
		SessionUUID:  session.UUID,
		NewEmail:     "new@example.com",
		EmailVersion: 3,
		CodeHash:     hash,
		ExpiresAt:    time.Now().Add(domain.EmailChangeCodeTTL).Unix(),
	}
}

func ageEmailChangeChallenge(t *testing.T, sessionUUID string, age time.Duration) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE email_change_challenges SET created_at = now() - $2::interval WHERE session_uuid = $1",
		sessionUUID, age.String(),
	)
	require.NoError(t, err)
}

func TestEmailChangePostgresRepository_Upsert(t *testing.T) {
	repo, user, session := setupEmailChangeRepoTest(t)
	ctx := context.Background()

	t.Run("success creates a challenge", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-1"), domain.EmailChangeCooldown)

		require.NoError(t, err)
		assert.Equal(t, user.UUID, challenge.UserUUID)
		assert.Equal(t, session.UUID, challenge.SessionUUID)
		assert.Equal(t, "new@example.com", challenge.NewEmail)
		assert.Equal(t, 3, challenge.EmailVersion)
		assert.Equal(t, "hash-1", challenge.CodeHash)
		assert.Equal(t, 0, challenge.Attempts)
		assert.InDelta(t, time.Now().Add(domain.EmailChangeCodeTTL).Unix(), challenge.ExpiresAt, 5)
	})

	t.Run("error - cooldown", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-2"), domain.EmailChangeCooldown)

		assert.Nil(t, challenge)
		var tooManyErr *domain.TooManyRequestsError
		require.True(t, errors.As(err, &tooManyErr))
		assert.Equal(t, "users.emailChange.cooldown", tooManyErr.Error())
	})

	t.Run("success replaces the challenge after the cooldown and resets attempts", func(t *testing.T) {
		_, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.EmailChangeMaxAttempts)
		require.NoError(t, err)
		ageEmailChangeChallenge(t, session.UUID, 2*domain.EmailChangeCooldown)
		replacement := newEmailChangeChallenge(user, session, "hash-3")
		replacement.NewEmail = "other@example.com"

		challenge, err := repo.Upsert(ctx, replacement, domain.EmailChangeCooldown)

		require.NoError(t, err)
		assert.Equal(t, "hash-3", challenge.CodeHash)
		assert.Equal(t, "other@example.com", challenge.NewEmail)
		assert.Equal(t, 0, challenge.Attempts)
	})

	t.Run("error - unknown session", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newEmailChangeChallenge(user, &domain.UserSession{UUID: uuid.NewString()}, "hash"), domain.EmailChangeCooldown)

		assert.Nil(t, challenge)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newEmailChangeChallenge(user, &domain.UserSession{UUID: "invalid"}, "hash"), domain.EmailChangeCooldown)

		assert.Nil(t, challenge)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestEmailChangePostgresRepository_Attempt(t *testing.T) {
	repo, user, session := setupEmailChangeRepoTest(t)
	ctx := context.Background()

	t.Run("error - no challenge", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.EmailChangeMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("success increments attempts until the maximum", func(t *testing.T) {
		_, err := repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-1"), domain.EmailChangeCooldown)
		require.NoError(t, err)

		for i := 1; i <= domain.EmailChangeMaxAttempts; i++ {
			challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.EmailChangeMaxAttempts)

			require.NoError(t, err)
			assert.Equal(t, "hash-1", challenge.CodeHash)
			assert.Equal(t, "new@example.com", challenge.NewEmail)
			assert.Equal(t, 3, challenge.EmailVersion)
			assert.Equal(t, i, challenge.Attempts)
		}

		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.EmailChangeMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - expired challenge", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE email_change_challenges SET attempts = 0, expires_at = now() - interval '1 minute' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.EmailChangeMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - challenge of another user", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE email_change_challenges SET expires_at = now() + interval '10 minutes' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Attempt(ctx, uuid.NewString(), session.UUID, domain.EmailChangeMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, "invalid", domain.EmailChangeMaxAttempts)

		assert.Nil(t, challenge)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestEmailChangePostgresRepository_Delete(t *testing.T) {
	repo, user, session := setupEmailChangeRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		_, err := repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-1"), domain.EmailChangeCooldown)
		require.NoError(t, err)

		err = repo.Delete(ctx, session.UUID)

		require.NoError(t, err)
		_, err = repo.Attempt(ctx, user.UUID, session.UUID, domain.EmailChangeMaxAttempts)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("success - nothing to delete", func(t *testing.T) {
		assert.NoError(t, repo.Delete(ctx, uuid.NewString()))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.Delete(ctx, "invalid")

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}
