package repositories_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSessionsRepoTest(t *testing.T) (domain.SessionsRepository, domain.UsersRepository, *domain.User) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	usersRepo := repositories.NewUsersPostgresRepository(testDB)
	user := seedUser(t, usersRepo)

	return repositories.NewSessionsPostgresRepository(testDB), usersRepo, user
}

func seedSession(t *testing.T, repo domain.SessionsRepository, userUUID string, jti string) *domain.UserSession {
	t.Helper()
	session, err := repo.Create(context.Background(), domain.UserSession{
		UserUUID:   userUUID,
		CurrentJTI: jti,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return session
}

func setSessionTimes(t *testing.T, sessionUUID string, lastUsedAt time.Time, expiresAt time.Time) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE user_sessions SET last_used_at = $2, expires_at = $3 WHERE uuid = $1",
		sessionUUID, lastUsedAt, expiresAt,
	)
	require.NoError(t, err)
}

func sessionExists(t *testing.T, repo domain.SessionsRepository, userUUID string, sessionUUID string) bool {
	t.Helper()
	_, err := repo.FindByUUID(context.Background(), userUUID, sessionUUID)
	if err == nil {
		return true
	}
	var notFoundErr *domain.NotFoundError
	require.True(t, errors.As(err, &notFoundErr), "unexpected error: %v", err)
	return false
}

func TestSessionsPostgresRepository_Create(t *testing.T) {
	repo, _, user := setupSessionsRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour).Unix()

		session, err := repo.Create(ctx, domain.UserSession{UserUUID: user.UUID, CurrentJTI: "jti-1", ExpiresAt: expiresAt})

		require.NoError(t, err)
		assert.NotEmpty(t, session.UUID)
		assert.Equal(t, user.UUID, session.UserUUID)
		assert.Equal(t, "jti-1", session.CurrentJTI)
		assert.Equal(t, expiresAt, session.ExpiresAt)
		assert.InDelta(t, time.Now().Unix(), session.CreatedAt, 5)
		assert.Equal(t, session.CreatedAt, session.LastUsedAt)
	})

	t.Run("error - unknown user", func(t *testing.T) {
		_, err := repo.Create(ctx, domain.UserSession{UserUUID: uuid.NewString(), CurrentJTI: "jti", ExpiresAt: time.Now().Add(time.Hour).Unix()})

		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - invalid user uuid", func(t *testing.T) {
		_, err := repo.Create(ctx, domain.UserSession{UserUUID: "invalid", CurrentJTI: "jti"})

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestSessionsPostgresRepository_FindByUUID(t *testing.T) {
	repo, usersRepo, user := setupSessionsRepoTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		created := seedSession(t, repo, user.UUID, "jti-find")

		found, err := repo.FindByUUID(ctx, user.UUID, created.UUID)

		require.NoError(t, err)
		assert.Equal(t, created, found)
	})

	t.Run("error - session of another user", func(t *testing.T) {
		created := seedSession(t, repo, user.UUID, "jti-other")
		other, err := usersRepo.Create(ctx, domain.User{Name: "Other", Email: "other@example.com", PasswordHash: "hash"})
		require.NoError(t, err)

		assert.False(t, sessionExists(t, repo, other.UUID, created.UUID))
	})

	t.Run("error - not found", func(t *testing.T) {
		assert.False(t, sessionExists(t, repo, user.UUID, uuid.NewString()))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		var validationErr *domain.ValidationError
		_, err := repo.FindByUUID(ctx, user.UUID, "invalid")
		assert.True(t, errors.As(err, &validationErr))
		_, err = repo.FindByUUID(ctx, "invalid", uuid.NewString())
		assert.True(t, errors.As(err, &validationErr))
	})

	t.Run("sessions are deleted with their user", func(t *testing.T) {
		doomed, err := usersRepo.Create(ctx, domain.User{Name: "Doomed", Email: "doomed@example.com", PasswordHash: "hash"})
		require.NoError(t, err)
		session := seedSession(t, repo, doomed.UUID, "jti-doomed")

		require.NoError(t, usersRepo.Delete(ctx, doomed.UUID))

		assert.False(t, sessionExists(t, repo, doomed.UUID, session.UUID))
	})
}

func TestSessionsPostgresRepository_RotateJTI(t *testing.T) {
	repo, _, user := setupSessionsRepoTest(t)
	ctx := context.Background()
	var notFoundErr *domain.NotFoundError

	t.Run("success - rotates only from the current jti", func(t *testing.T) {
		session := seedSession(t, repo, user.UUID, "jti-1")
		setSessionTimes(t, session.UUID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

		require.NoError(t, repo.RotateJTI(ctx, user.UUID, session.UUID, "jti-1", "jti-2"))

		rotated, err := repo.FindByUUID(ctx, user.UUID, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, "jti-2", rotated.CurrentJTI)
		assert.InDelta(t, time.Now().Unix(), rotated.LastUsedAt, 5)
		assert.Equal(t, session.CreatedAt, rotated.CreatedAt)
		err = repo.RotateJTI(ctx, user.UUID, session.UUID, "jti-1", "jti-3")
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - other sessions are not affected", func(t *testing.T) {
		first := seedSession(t, repo, user.UUID, "shared-jti")
		second := seedSession(t, repo, user.UUID, "shared-jti")

		require.NoError(t, repo.RotateJTI(ctx, user.UUID, first.UUID, "shared-jti", "next"))

		untouched, err := repo.FindByUUID(ctx, user.UUID, second.UUID)
		require.NoError(t, err)
		assert.Equal(t, "shared-jti", untouched.CurrentJTI)
	})

	t.Run("error - wrong user", func(t *testing.T) {
		session := seedSession(t, repo, user.UUID, "jti-owner")

		err := repo.RotateJTI(ctx, uuid.NewString(), session.UUID, "jti-owner", "next")

		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - concurrent rotations from the same jti have a single winner", func(t *testing.T) {
		session := seedSession(t, repo, user.UUID, "concurrent")

		const rotations = 10
		errs := make([]error, rotations)
		var wg sync.WaitGroup
		for i := range rotations {
			wg.Go(func() {
				errs[i] = repo.RotateJTI(ctx, user.UUID, session.UUID, "concurrent", uuid.NewString())
			})
		}
		wg.Wait()

		succeeded := 0
		for _, err := range errs {
			if err == nil {
				succeeded++
				continue
			}
			assert.True(t, errors.As(err, &notFoundErr))
		}
		assert.Equal(t, 1, succeeded)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(repo.RotateJTI(ctx, user.UUID, "invalid", "a", "b"), &validationErr))
		assert.True(t, errors.As(repo.RotateJTI(ctx, "invalid", uuid.NewString(), "a", "b"), &validationErr))
	})
}

func TestSessionsPostgresRepository_Delete(t *testing.T) {
	repo, _, user := setupSessionsRepoTest(t)
	ctx := context.Background()

	t.Run("success - deletes only the given session", func(t *testing.T) {
		doomed := seedSession(t, repo, user.UUID, "doomed")
		kept := seedSession(t, repo, user.UUID, "kept")

		require.NoError(t, repo.Delete(ctx, user.UUID, doomed.UUID))

		assert.False(t, sessionExists(t, repo, user.UUID, doomed.UUID))
		assert.True(t, sessionExists(t, repo, user.UUID, kept.UUID))
	})

	t.Run("success - idempotent", func(t *testing.T) {
		assert.NoError(t, repo.Delete(ctx, user.UUID, uuid.NewString()))
	})

	t.Run("success - ignores sessions of another user", func(t *testing.T) {
		session := seedSession(t, repo, user.UUID, "owned")

		require.NoError(t, repo.Delete(ctx, uuid.NewString(), session.UUID))

		assert.True(t, sessionExists(t, repo, user.UUID, session.UUID))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(repo.Delete(ctx, user.UUID, "invalid"), &validationErr))
	})
}

func TestSessionsPostgresRepository_DeleteExpiredByUser(t *testing.T) {
	repo, usersRepo, user := setupSessionsRepoTest(t)
	ctx := context.Background()
	const idleTimeout = 24 * time.Hour

	active := seedSession(t, repo, user.UUID, "active")
	expired := seedSession(t, repo, user.UUID, "expired")
	setSessionTimes(t, expired.UUID, time.Now(), time.Now().Add(-time.Minute))
	idle := seedSession(t, repo, user.UUID, "idle")
	setSessionTimes(t, idle.UUID, time.Now().Add(-idleTimeout-time.Minute), time.Now().Add(time.Hour))
	other, err := usersRepo.Create(ctx, domain.User{Name: "Other", Email: "other@example.com", PasswordHash: "hash"})
	require.NoError(t, err)
	otherExpired := seedSession(t, repo, other.UUID, "other-expired")
	setSessionTimes(t, otherExpired.UUID, time.Now(), time.Now().Add(-time.Minute))

	require.NoError(t, repo.DeleteExpiredByUser(ctx, user.UUID, idleTimeout))

	assert.True(t, sessionExists(t, repo, user.UUID, active.UUID))
	assert.False(t, sessionExists(t, repo, user.UUID, expired.UUID))
	assert.False(t, sessionExists(t, repo, user.UUID, idle.UUID))
	assert.True(t, sessionExists(t, repo, other.UUID, otherExpired.UUID))
}

func TestSessionsPostgresRepository_DeleteOldestBeyond(t *testing.T) {
	repo, usersRepo, user := setupSessionsRepoTest(t)
	ctx := context.Background()

	now := time.Now()
	sessions := make([]*domain.UserSession, 4)
	for i := range sessions {
		sessions[i] = seedSession(t, repo, user.UUID, uuid.NewString())
		setSessionTimes(t, sessions[i].UUID, now.Add(-time.Duration(i)*time.Minute), now.Add(time.Hour))
	}
	other, err := usersRepo.Create(ctx, domain.User{Name: "Other", Email: "other@example.com", PasswordHash: "hash"})
	require.NoError(t, err)
	otherSession := seedSession(t, repo, other.UUID, "other")
	setSessionTimes(t, otherSession.UUID, now.Add(-time.Hour), now.Add(time.Hour))

	require.NoError(t, repo.DeleteOldestBeyond(ctx, user.UUID, 2))

	assert.True(t, sessionExists(t, repo, user.UUID, sessions[0].UUID))
	assert.True(t, sessionExists(t, repo, user.UUID, sessions[1].UUID))
	assert.False(t, sessionExists(t, repo, user.UUID, sessions[2].UUID))
	assert.False(t, sessionExists(t, repo, user.UUID, sessions[3].UUID))
	assert.True(t, sessionExists(t, repo, other.UUID, otherSession.UUID))
}
