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

func setupStepUpRepoTest(t *testing.T) (domain.StepUpRepository, *domain.User, *domain.UserSession) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	user := seedUser(t, repositories.NewUsersPostgresRepository(testDB))
	session := seedSession(t, repositories.NewSessionsPostgresRepository(testDB), user.UUID, "jti-1")

	return repositories.NewStepUpPostgresRepository(testDB), user, session
}

func newChallenge(user *domain.User, session *domain.UserSession, hash string) domain.StepUpChallenge {
	return domain.StepUpChallenge{
		UserUUID:    user.UUID,
		SessionUUID: session.UUID,
		CodeHash:    hash,
		ExpiresAt:   time.Now().Add(domain.StepUpCodeTTL).Unix(),
	}
}

func ageChallenge(t *testing.T, sessionUUID string, age time.Duration) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE step_up_challenges SET created_at = now() - $2::interval WHERE session_uuid = $1",
		sessionUUID, age.String(),
	)
	require.NoError(t, err)
}

func TestStepUpPostgresRepository_Upsert(t *testing.T) {
	repo, user, session := setupStepUpRepoTest(t)
	ctx := context.Background()

	t.Run("success creates a challenge", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newChallenge(user, session, "hash-1"), domain.StepUpCooldown)

		require.NoError(t, err)
		assert.Equal(t, user.UUID, challenge.UserUUID)
		assert.Equal(t, session.UUID, challenge.SessionUUID)
		assert.Equal(t, "hash-1", challenge.CodeHash)
		assert.Equal(t, 0, challenge.Attempts)
		assert.InDelta(t, time.Now().Add(domain.StepUpCodeTTL).Unix(), challenge.ExpiresAt, 5)
		assert.InDelta(t, time.Now().Unix(), challenge.CreatedAt, 5)
	})

	t.Run("error - cooldown", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newChallenge(user, session, "hash-2"), domain.StepUpCooldown)

		assert.Nil(t, challenge)
		var tooManyErr *domain.TooManyRequestsError
		require.True(t, errors.As(err, &tooManyErr))
		assert.Equal(t, "auth.stepUp.cooldown", tooManyErr.Error())
	})

	t.Run("success replaces the challenge after the cooldown and resets attempts", func(t *testing.T) {
		_, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.StepUpMaxAttempts)
		require.NoError(t, err)
		ageChallenge(t, session.UUID, 2*domain.StepUpCooldown)

		challenge, err := repo.Upsert(ctx, newChallenge(user, session, "hash-3"), domain.StepUpCooldown)

		require.NoError(t, err)
		assert.Equal(t, "hash-3", challenge.CodeHash)
		assert.Equal(t, 0, challenge.Attempts)
	})

	t.Run("error - unknown session", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newChallenge(user, &domain.UserSession{UUID: uuid.NewString()}, "hash"), domain.StepUpCooldown)

		assert.Nil(t, challenge)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		challenge, err := repo.Upsert(ctx, newChallenge(user, &domain.UserSession{UUID: "invalid"}, "hash"), domain.StepUpCooldown)

		assert.Nil(t, challenge)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestStepUpPostgresRepository_Attempt(t *testing.T) {
	repo, user, session := setupStepUpRepoTest(t)
	ctx := context.Background()

	t.Run("error - no challenge", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		var unauthorizedErr *domain.UnauthorizedError
		require.True(t, errors.As(err, &unauthorizedErr))
		assert.Equal(t, "auth.stepUp.noChallenge", unauthorizedErr.Error())
	})

	t.Run("success increments attempts until the maximum", func(t *testing.T) {
		_, err := repo.Upsert(ctx, newChallenge(user, session, "hash-1"), domain.StepUpCooldown)
		require.NoError(t, err)

		for i := 1; i <= domain.StepUpMaxAttempts; i++ {
			challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.StepUpMaxAttempts)

			require.NoError(t, err)
			assert.Equal(t, "hash-1", challenge.CodeHash)
			assert.Equal(t, i, challenge.Attempts)
		}

		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
	})

	t.Run("error - expired challenge", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE step_up_challenges SET attempts = 0, expires_at = now() - interval '1 minute' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
	})

	t.Run("error - challenge of another user", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE step_up_challenges SET expires_at = now() + interval '10 minutes' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Attempt(ctx, uuid.NewString(), session.UUID, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, "invalid", domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestStepUpPostgresRepository_Delete(t *testing.T) {
	repo, user, session := setupStepUpRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		_, err := repo.Upsert(ctx, newChallenge(user, session, "hash-1"), domain.StepUpCooldown)
		require.NoError(t, err)

		err = repo.Delete(ctx, session.UUID)

		require.NoError(t, err)
		_, err = repo.Attempt(ctx, user.UUID, session.UUID, domain.StepUpMaxAttempts)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
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
