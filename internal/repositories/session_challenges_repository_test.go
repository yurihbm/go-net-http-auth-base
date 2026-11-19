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

func setupSessionChallengesRepoTest(t *testing.T) (domain.SessionChallengeRepository, *domain.User, *domain.UserSession) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	user := seedUser(t, repositories.NewUsersPostgresRepository(testDB))
	session := seedSession(t, repositories.NewSessionsPostgresRepository(testDB), user.UUID, "jti-1")

	return repositories.NewSessionChallengesPostgresRepository(testDB), user, session
}

func newStepUpChallenge(user *domain.User, session *domain.UserSession, hash string) domain.SessionChallenge {
	return domain.SessionChallenge{
		UserUUID:    user.UUID,
		SessionUUID: session.UUID,
		Purpose:     domain.SessionChallengeStepUp,
		CodeHash:    hash,
		ExpiresAt:   time.Now().Add(domain.StepUpCodeTTL).Unix(),
	}
}

func newEmailChangeChallenge(user *domain.User, session *domain.UserSession, hash string) domain.SessionChallenge {
	return domain.SessionChallenge{
		UserUUID:     user.UUID,
		SessionUUID:  session.UUID,
		Purpose:      domain.SessionChallengeEmailChange,
		NewEmail:     "new@example.com",
		EmailVersion: 3,
		CodeHash:     hash,
		ExpiresAt:    time.Now().Add(domain.EmailChangeCodeTTL).Unix(),
	}
}

func ageChallenge(t *testing.T, sessionUUID string, purpose domain.SessionChallengePurpose, age time.Duration) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE session_challenges SET created_at = now() - $3::interval WHERE session_uuid = $1 AND purpose = $2",
		sessionUUID, purpose, age.String(),
	)
	require.NoError(t, err)
}

func challengeAttempts(t *testing.T, sessionUUID string, purpose domain.SessionChallengePurpose) int {
	var attempts int
	require.NoError(t, testDB.QueryRow(context.Background(),
		"SELECT attempts FROM session_challenges WHERE session_uuid = $1 AND purpose = $2", sessionUUID, purpose,
	).Scan(&attempts))
	return attempts
}

func TestSessionChallengesPostgresRepository_Upsert(t *testing.T) {
	repo, user, session := setupSessionChallengesRepoTest(t)
	ctx := context.Background()

	t.Run("success creates a challenge per purpose for the same session", func(t *testing.T) {
		require.NoError(t, repo.Upsert(ctx, newStepUpChallenge(user, session, "hash-step-up"), domain.StepUpCooldown))
		require.NoError(t, repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-email"), domain.EmailChangeCooldown))

		stepUp, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)
		require.NoError(t, err)
		assert.Equal(t, "hash-step-up", stepUp.CodeHash)
		assert.Empty(t, stepUp.NewEmail)
		assert.InDelta(t, time.Now().Add(domain.StepUpCodeTTL).Unix(), stepUp.ExpiresAt, 5)

		emailChange, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)
		require.NoError(t, err)
		assert.Equal(t, "hash-email", emailChange.CodeHash)
		assert.Equal(t, "new@example.com", emailChange.NewEmail)
		assert.Equal(t, 3, emailChange.EmailVersion)
	})

	t.Run("error - cooldown per purpose", func(t *testing.T) {
		err := repo.Upsert(ctx, newStepUpChallenge(user, session, "hash-2"), domain.StepUpCooldown)

		var tooManyErr *domain.TooManyRequestsError
		require.True(t, errors.As(err, &tooManyErr))
		assert.Equal(t, "auth.stepUp.cooldown", tooManyErr.Error())

		err = repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-2"), domain.EmailChangeCooldown)

		require.True(t, errors.As(err, &tooManyErr))
		assert.Equal(t, "users.emailChange.cooldown", tooManyErr.Error())
	})

	t.Run("success replaces the challenge after the cooldown and resets attempts", func(t *testing.T) {
		ageChallenge(t, session.UUID, domain.SessionChallengeEmailChange, 2*domain.EmailChangeCooldown)
		replacement := newEmailChangeChallenge(user, session, "hash-3")
		replacement.NewEmail = "other@example.com"

		require.NoError(t, repo.Upsert(ctx, replacement, domain.EmailChangeCooldown))

		assert.Equal(t, 0, challengeAttempts(t, session.UUID, domain.SessionChallengeEmailChange))
		assert.Equal(t, 1, challengeAttempts(t, session.UUID, domain.SessionChallengeStepUp))
		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)
		require.NoError(t, err)
		assert.Equal(t, "hash-3", challenge.CodeHash)
		assert.Equal(t, "other@example.com", challenge.NewEmail)
	})

	t.Run("error - unknown session", func(t *testing.T) {
		err := repo.Upsert(ctx, newStepUpChallenge(user, &domain.UserSession{UUID: uuid.NewString()}, "hash"), domain.StepUpCooldown)

		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.Upsert(ctx, newStepUpChallenge(user, &domain.UserSession{UUID: "invalid"}, "hash"), domain.StepUpCooldown)

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestSessionChallengesPostgresRepository_Find(t *testing.T) {
	repo, user, session := setupSessionChallengesRepoTest(t)
	ctx := context.Background()

	t.Run("error - no challenge", func(t *testing.T) {
		challenge, err := repo.Find(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("success returns the challenge without counting an attempt", func(t *testing.T) {
		require.NoError(t, repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-1"), domain.EmailChangeCooldown))

		challenge, err := repo.Find(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange)

		require.NoError(t, err)
		assert.Equal(t, "new@example.com", challenge.NewEmail)
		assert.Equal(t, 3, challenge.EmailVersion)
		assert.Equal(t, 0, challengeAttempts(t, session.UUID, domain.SessionChallengeEmailChange))
	})

	t.Run("error - other purpose", func(t *testing.T) {
		challenge, err := repo.Find(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrStepUpNoChallenge)
	})

	t.Run("error - challenge of another user", func(t *testing.T) {
		challenge, err := repo.Find(ctx, uuid.NewString(), session.UUID, domain.SessionChallengeEmailChange)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - expired challenge", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE session_challenges SET expires_at = now() - interval '1 minute' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Find(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		challenge, err := repo.Find(ctx, user.UUID, "invalid", domain.SessionChallengeEmailChange)

		assert.Nil(t, challenge)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestSessionChallengesPostgresRepository_Attempt(t *testing.T) {
	repo, user, session := setupSessionChallengesRepoTest(t)
	ctx := context.Background()

	t.Run("error - no challenge", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrStepUpNoChallenge)
	})

	t.Run("success increments attempts until the maximum", func(t *testing.T) {
		require.NoError(t, repo.Upsert(ctx, newStepUpChallenge(user, session, "hash-1"), domain.StepUpCooldown))

		for i := 1; i <= domain.StepUpMaxAttempts; i++ {
			challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)

			require.NoError(t, err)
			assert.Equal(t, "hash-1", challenge.CodeHash)
			assert.Equal(t, i, challengeAttempts(t, session.UUID, domain.SessionChallengeStepUp))
		}

		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrStepUpNoChallenge)
	})

	t.Run("error - other purpose", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - expired challenge", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE session_challenges SET attempts = 0, expires_at = now() - interval '1 minute' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrStepUpNoChallenge)
	})

	t.Run("error - challenge of another user", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE session_challenges SET expires_at = now() + interval '10 minutes' WHERE session_uuid = $1", session.UUID)
		require.NoError(t, err)

		challenge, err := repo.Attempt(ctx, uuid.NewString(), session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		assert.ErrorIs(t, err, domain.ErrStepUpNoChallenge)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		challenge, err := repo.Attempt(ctx, user.UUID, "invalid", domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)

		assert.Nil(t, challenge)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestSessionChallengesPostgresRepository_Delete(t *testing.T) {
	repo, user, session := setupSessionChallengesRepoTest(t)
	ctx := context.Background()

	t.Run("success deletes only the given purpose", func(t *testing.T) {
		require.NoError(t, repo.Upsert(ctx, newStepUpChallenge(user, session, "hash-1"), domain.StepUpCooldown))
		require.NoError(t, repo.Upsert(ctx, newEmailChangeChallenge(user, session, "hash-2"), domain.EmailChangeCooldown))

		err := repo.Delete(ctx, session.UUID, domain.SessionChallengeStepUp)

		require.NoError(t, err)
		_, err = repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)
		assert.ErrorIs(t, err, domain.ErrStepUpNoChallenge)
		_, err = repo.Attempt(ctx, user.UUID, session.UUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)
		assert.NoError(t, err)
	})

	t.Run("success - deleting the session cascades", func(t *testing.T) {
		require.NoError(t, repositories.NewSessionsPostgresRepository(testDB).Delete(ctx, user.UUID, session.UUID))

		var count int
		require.NoError(t, testDB.QueryRow(ctx, "SELECT count(*) FROM session_challenges").Scan(&count))
		assert.Zero(t, count)
	})

	t.Run("success - nothing to delete", func(t *testing.T) {
		assert.NoError(t, repo.Delete(ctx, uuid.NewString(), domain.SessionChallengeStepUp))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.Delete(ctx, "invalid", domain.SessionChallengeStepUp)

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}
