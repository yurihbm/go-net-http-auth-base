package repositories_test

import (
	"context"
	"errors"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupUsersRepoTest(t *testing.T) domain.UsersRepository {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	ctx := context.Background()
	repo := repositories.NewUsersPostgresRepository(testDB)
	require.NotNil(t, repo)

	truncateTables(ctx, testDB)

	return repo
}

func seedUser(t *testing.T, repo domain.UsersRepository) *domain.User {
	user := domain.User{
		Name:         "John Doe",
		Email:        "john.doe@example.com",
		PasswordHash: "hashed_password",
		Role:         domain.RoleUser,
	}

	createdUser, err := repo.FindByEmail(context.Background(), user.Email)
	if err != nil || createdUser == nil {
		createdUser, err = repo.Create(context.Background(), user)
		require.NoError(t, err)
		require.NotNil(t, createdUser)
	}

	return createdUser
}

func TestUsersPostgresRepository_Create(t *testing.T) {
	repo := setupUsersRepoTest(t)

	t.Run("success", func(t *testing.T) {
		user := domain.User{
			Name:         "John Doe",
			Email:        "john.doe@example.com",
			PasswordHash: "hashed_password",
			Role:         domain.RoleUser,
		}

		createdUser, err := repo.Create(context.Background(), user)
		require.NoError(t, err)
		assert.NotEmpty(t, createdUser.UUID)
		assert.NotEqual(t, createdUser.CreatedAt, 0)
		assert.NotEqual(t, createdUser.UpdatedAt, 0)
		assert.Equal(t, user.Name, createdUser.Name)
		assert.Equal(t, user.Email, createdUser.Email)
		assert.Equal(t, user.PasswordHash, createdUser.PasswordHash)
		assert.Equal(t, domain.RoleUser, createdUser.Role)
	})

	t.Run("duplicate email", func(t *testing.T) {
		email := "jane.doe@example.com"

		// Create first user
		user1 := domain.User{
			Name:         "Jane Doe",
			Email:        email,
			PasswordHash: "hashed_password",
		}
		_, err := repo.Create(context.Background(), user1)
		require.NoError(t, err)

		// Try to create second user with same email
		user2 := domain.User{
			Name:         "Jane Doe",
			Email:        email,
			PasswordHash: "another_password",
		}

		_, err = repo.Create(context.Background(), user2)
		require.Error(t, err)
		var conflictErr *domain.ConflictError
		assert.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
	})

	t.Run("error - duplicate email differing only in case", func(t *testing.T) {
		_, err := repo.Create(context.Background(), domain.User{Name: "Case", Email: "case.user@example.com", PasswordHash: "h"})
		require.NoError(t, err)

		_, err = repo.Create(context.Background(), domain.User{Name: "Case", Email: "Case.User@example.com", PasswordHash: "h"})
		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
	})
}

func TestUsersPostgresRepository_FindByUUID(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		foundUser, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		require.NoError(t, err)
		require.NotNil(t, foundUser)
		assert.Equal(t, createdUser.UUID, foundUser.UUID)
		assert.Equal(t, createdUser.Name, foundUser.Name)
		assert.Equal(t, createdUser.Email, foundUser.Email)
		assert.Equal(t, domain.RoleUser, foundUser.Role)
	})

	t.Run("not found", func(t *testing.T) {
		nonExistentUUID := uuid.Must(uuid.NewV7()).String()
		user, err := repo.FindByUUID(context.Background(), nonExistentUUID)
		require.Error(t, err)
		assert.Nil(t, user)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("invalid uuid", func(t *testing.T) {
		user, err := repo.FindByUUID(context.Background(), "invalid-uuid")
		require.Error(t, err)
		assert.Nil(t, user)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_FindByEmail(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		foundUser, err := repo.FindByEmail(context.Background(), createdUser.Email)
		require.NoError(t, err)
		require.NotNil(t, foundUser)
		assert.Equal(t, createdUser.UUID, foundUser.UUID)
		assert.Equal(t, createdUser.Name, foundUser.Name)
		assert.Equal(t, createdUser.Email, foundUser.Email)
		assert.Equal(t, domain.RoleUser, foundUser.Role)
	})

	t.Run("not found", func(t *testing.T) {
		user, err := repo.FindByEmail(context.Background(), "nonexistent@example.com")
		require.Error(t, err)
		assert.Nil(t, user)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})
}

func TestUsersPostgresRepository_Update(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		originalEmail := createdUser.Email
		createdUser.Name = "John Doe Updated"
		createdUser.Email = "john.doe.updated@example.com"

		returnedUser, err := repo.Update(context.Background(), *createdUser)
		require.NoError(t, err)
		require.NotNil(t, returnedUser)
		assert.Equal(t, createdUser.UUID, returnedUser.UUID)
		assert.Equal(t, "John Doe Updated", returnedUser.Name)
		assert.Equal(t, originalEmail, returnedUser.Email)
		assert.Equal(t, createdUser.Role, returnedUser.Role)
		assert.GreaterOrEqual(t, returnedUser.UpdatedAt, createdUser.CreatedAt)

		updatedUser, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		require.NoError(t, err)
		require.NotNil(t, updatedUser)
		assert.Equal(t, "John Doe Updated", updatedUser.Name)
		assert.Equal(t, originalEmail, updatedUser.Email)
	})

	t.Run("error - user not found", func(t *testing.T) {
		returnedUser, err := repo.Update(context.Background(), domain.User{UUID: uuid.Must(uuid.NewV7()).String()})
		require.Error(t, err)
		assert.Nil(t, returnedUser)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("invalid uuid", func(t *testing.T) {
		invalidUser := domain.User{UUID: "invalid"}
		returnedUser, err := repo.Update(context.Background(), invalidUser)
		require.Error(t, err)
		assert.Nil(t, returnedUser)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_UpdateEmail(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success sets the email and bumps the version", func(t *testing.T) {
		require.Equal(t, 0, createdUser.EmailVersion)
		require.Zero(t, createdUser.EmailChangedAt)
		changedAt := time.Now()

		returnedUser, err := repo.UpdateEmail(context.Background(), createdUser.UUID, "john.new@example.com", 0, &changedAt)

		require.NoError(t, err)
		assert.Equal(t, "john.new@example.com", returnedUser.Email)
		assert.Equal(t, 1, returnedUser.EmailVersion)
		assert.Equal(t, changedAt.Unix(), returnedUser.EmailChangedAt)
		found, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		require.NoError(t, err)
		assert.Equal(t, "john.new@example.com", found.Email)
		assert.Equal(t, 1, found.EmailVersion)
	})

	t.Run("success with a nil changedAt clears it", func(t *testing.T) {
		returnedUser, err := repo.UpdateEmail(context.Background(), createdUser.UUID, "john.revert@example.com", 1, nil)

		require.NoError(t, err)
		assert.Equal(t, 2, returnedUser.EmailVersion)
		assert.Zero(t, returnedUser.EmailChangedAt)
	})

	t.Run("error - stale version", func(t *testing.T) {
		returnedUser, err := repo.UpdateEmail(context.Background(), createdUser.UUID, "john.stale@example.com", 0, nil)

		assert.Nil(t, returnedUser)
		var unauthorizedErr *domain.UnauthorizedError
		require.True(t, errors.As(err, &unauthorizedErr))
		assert.Equal(t, "users.emailChange.staleToken", unauthorizedErr.Error())
	})

	t.Run("error - email taken", func(t *testing.T) {
		_, err := repo.Create(context.Background(), domain.User{Name: "Taken", Email: "taken@example.com", PasswordHash: "hash"})
		require.NoError(t, err)

		returnedUser, err := repo.UpdateEmail(context.Background(), createdUser.UUID, "Taken@Example.com", 2, nil)

		assert.Nil(t, returnedUser)
		var conflictErr *domain.ConflictError
		assert.True(t, errors.As(err, &conflictErr))
	})

	t.Run("error - user not found", func(t *testing.T) {
		returnedUser, err := repo.UpdateEmail(context.Background(), uuid.Must(uuid.NewV7()).String(), "ghost@example.com", 0, nil)

		assert.Nil(t, returnedUser)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		returnedUser, err := repo.UpdateEmail(context.Background(), "invalid", "ghost@example.com", 0, nil)

		assert.Nil(t, returnedUser)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_UpdatePassword(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success without a version check", func(t *testing.T) {
		updated, err := repo.UpdatePassword(context.Background(), createdUser.UUID, "new_hash", nil)

		require.NoError(t, err)
		assert.Equal(t, "new_hash", updated.PasswordHash)
		found, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		require.NoError(t, err)
		assert.Equal(t, "new_hash", found.PasswordHash)
	})

	t.Run("success when the email version matches", func(t *testing.T) {
		version := createdUser.EmailVersion

		updated, err := repo.UpdatePassword(context.Background(), createdUser.UUID, "versioned_hash", &version)

		require.NoError(t, err)
		assert.Equal(t, "versioned_hash", updated.PasswordHash)
	})

	t.Run("error - stale email version keeps the password", func(t *testing.T) {
		stale := createdUser.EmailVersion + 1

		updated, err := repo.UpdatePassword(context.Background(), createdUser.UUID, "stale_hash", &stale)

		assert.Nil(t, updated)
		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		found, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		require.NoError(t, err)
		assert.Equal(t, "versioned_hash", found.PasswordHash)
	})

	t.Run("error - user not found", func(t *testing.T) {
		updated, err := repo.UpdatePassword(context.Background(), uuid.Must(uuid.NewV7()).String(), "hash", nil)

		assert.Nil(t, updated)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		updated, err := repo.UpdatePassword(context.Background(), "invalid", "hash", nil)

		assert.Nil(t, updated)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})

	t.Run("error - canceled context", func(t *testing.T) {
		_, err := repo.UpdatePassword(canceledContext(), createdUser.UUID, "hash", nil)

		assertInternalError(t, err)
	})
}

func TestUsersPostgresRepository_UpdateRole(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		require.Equal(t, domain.RoleUser, createdUser.Role)

		returnedUser, err := repo.UpdateRole(context.Background(), createdUser.UUID, domain.RoleAdmin)

		require.NoError(t, err)
		assert.Equal(t, createdUser.UUID, returnedUser.UUID)
		assert.Equal(t, domain.RoleAdmin, returnedUser.Role)
		found, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		require.NoError(t, err)
		assert.Equal(t, domain.RoleAdmin, found.Role)
	})

	t.Run("error - user not found", func(t *testing.T) {
		returnedUser, err := repo.UpdateRole(context.Background(), uuid.Must(uuid.NewV7()).String(), domain.RoleAdmin)

		assert.Nil(t, returnedUser)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		returnedUser, err := repo.UpdateRole(context.Background(), "invalid", domain.RoleAdmin)

		assert.Nil(t, returnedUser)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_ReserveStepUpGuess(t *testing.T) {
	repo := setupUsersRepoTest(t)
	ctx := context.Background()
	user, err := repo.Create(ctx, domain.User{Name: "Failures", Email: "failures@example.com", PasswordHash: "hash", Role: domain.RoleUser})
	require.NoError(t, err)
	window := domain.StepUpUserFailureWindow

	t.Run("success - starts the window and increments", func(t *testing.T) {
		require.NoError(t, repo.ReserveStepUpGuess(ctx, user.UUID, window))
		require.NoError(t, repo.ReserveStepUpGuess(ctx, user.UUID, window))

		found, err := repo.FindByUUID(ctx, user.UUID)
		require.NoError(t, err)
		assert.Equal(t, 2, found.StepUpFailures)
		assert.WithinDuration(t, time.Now(), time.Unix(found.StepUpFailuresWindowStart, 0), 5*time.Second)
	})

	t.Run("success - expired window restarts the count", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET step_up_failures = 20, step_up_failures_window_start = now() - interval '25 hours' WHERE uuid = $1", user.UUID)
		require.NoError(t, err)

		require.NoError(t, repo.ReserveStepUpGuess(ctx, user.UUID, window))

		found, err := repo.FindByUUID(ctx, user.UUID)
		require.NoError(t, err)
		assert.Equal(t, 1, found.StepUpFailures)
		assert.WithinDuration(t, time.Now(), time.Unix(found.StepUpFailuresWindowStart, 0), 5*time.Second)
	})

	t.Run("error - cap reached inside the window", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET step_up_failures = $2, step_up_failures_window_start = now() WHERE uuid = $1", user.UUID, domain.StepUpMaxUserFailures)
		require.NoError(t, err)

		err = repo.ReserveStepUpGuess(ctx, user.UUID, window)

		assert.ErrorIs(t, err, domain.ErrStepUpUserLocked)
	})

	t.Run("success - concurrent reservations never exceed the cap", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET step_up_failures = 0, step_up_failures_window_start = now() WHERE uuid = $1", user.UUID)
		require.NoError(t, err)

		var wg sync.WaitGroup
		var mu sync.Mutex
		reserved := 0
		for range domain.StepUpMaxUserFailures + 10 {
			wg.Go(func() {
				if err := repo.ReserveStepUpGuess(ctx, user.UUID, window); err == nil {
					mu.Lock()
					reserved++
					mu.Unlock()
				} else {
					assert.ErrorIs(t, err, domain.ErrStepUpUserLocked)
				}
			})
		}
		wg.Wait()

		assert.Equal(t, domain.StepUpMaxUserFailures, reserved)
		found, err := repo.FindByUUID(ctx, user.UUID)
		require.NoError(t, err)
		assert.Equal(t, domain.StepUpMaxUserFailures, found.StepUpFailures)
	})

	t.Run("error - user not found", func(t *testing.T) {
		err := repo.ReserveStepUpGuess(ctx, uuid.Must(uuid.NewV7()).String(), window)

		assert.ErrorIs(t, err, domain.ErrStepUpUserLocked)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.ReserveStepUpGuess(ctx, "invalid-uuid", window)

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_RefundStepUpGuess(t *testing.T) {
	repo := setupUsersRepoTest(t)
	ctx := context.Background()
	user, err := repo.Create(ctx, domain.User{Name: "Failures", Email: "failures@example.com", PasswordHash: "hash", Role: domain.RoleUser})
	require.NoError(t, err)

	t.Run("success - decrements the count", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET step_up_failures = 3, step_up_failures_window_start = now() WHERE uuid = $1", user.UUID)
		require.NoError(t, err)

		require.NoError(t, repo.RefundStepUpGuess(ctx, user.UUID))

		found, err := repo.FindByUUID(ctx, user.UUID)
		require.NoError(t, err)
		assert.Equal(t, 2, found.StepUpFailures)
	})

	t.Run("success - never goes below zero", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET step_up_failures = 0 WHERE uuid = $1", user.UUID)
		require.NoError(t, err)

		require.NoError(t, repo.RefundStepUpGuess(ctx, user.UUID))

		found, err := repo.FindByUUID(ctx, user.UUID)
		require.NoError(t, err)
		assert.Equal(t, 0, found.StepUpFailures)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.RefundStepUpGuess(ctx, "invalid-uuid")

		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_Delete(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		err := repo.Delete(context.Background(), createdUser.UUID)
		require.NoError(t, err)

		deletedUser, err := repo.FindByUUID(context.Background(), createdUser.UUID)
		assert.Error(t, err)
		assert.Nil(t, deletedUser)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		err := repo.Delete(context.Background(), "invalid-uuid")
		require.Error(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestUsersPostgresRepository_CaseInsensitiveEmail(t *testing.T) {
	repo := setupUsersRepoTest(t)

	_, err := repo.Create(context.Background(), domain.User{Name: "Jane", Email: "jane@example.com", PasswordHash: "hash"})
	require.NoError(t, err)

	_, err = repo.Create(context.Background(), domain.User{Name: "Jane Upper", Email: "Jane@Example.com", PasswordHash: "hash"})

	require.Error(t, err)
	var conflictErr *domain.ConflictError
	assert.True(t, errors.As(err, &conflictErr))
	assert.Equal(t, "users.email.conflict", conflictErr.Error())
}

func TestUsersPostgresRepository_IsEmailReserved(t *testing.T) {
	repo := setupUsersRepoTest(t)
	user := seedUser(t, repo)
	ctx := context.Background()

	t.Run("not reserved before any change", func(t *testing.T) {
		reserved, err := repo.IsEmailReserved(ctx, user.Email)

		require.NoError(t, err)
		assert.False(t, reserved)
	})

	t.Run("reserved inside the lock window, case-insensitively", func(t *testing.T) {
		changedAt := time.Now().Add(-time.Hour)
		_, err := repo.UpdateEmail(ctx, user.UUID, "john.new@example.com", 0, &changedAt)
		require.NoError(t, err)

		reserved, err := repo.IsEmailReserved(ctx, "John.Doe@Example.com")

		require.NoError(t, err)
		assert.True(t, reserved)
		reserved, err = repo.IsEmailReserved(ctx, "john.new@example.com")
		require.NoError(t, err)
		assert.False(t, reserved)
	})

	t.Run("not reserved outside the lock window", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET email_changed_at = now() - interval '73 hours' WHERE uuid = $1", user.UUID)
		require.NoError(t, err)

		reserved, err := repo.IsEmailReserved(ctx, user.Email)

		require.NoError(t, err)
		assert.False(t, reserved)
	})

	t.Run("released after a revert", func(t *testing.T) {
		_, err := testDB.Exec(ctx, "UPDATE users SET email_changed_at = now() WHERE uuid = $1", user.UUID)
		require.NoError(t, err)
		reserved, err := repo.IsEmailReserved(ctx, user.Email)
		require.NoError(t, err)
		require.True(t, reserved)

		_, err = repo.UpdateEmail(ctx, user.UUID, user.Email, 1, nil)
		require.NoError(t, err)

		reserved, err = repo.IsEmailReserved(ctx, user.Email)
		require.NoError(t, err)
		assert.False(t, reserved)
	})

	t.Run("error - canceled context", func(t *testing.T) {
		reserved, err := repo.IsEmailReserved(canceledContext(), user.Email)
		assertInternalError(t, err)
		assert.False(t, reserved)
	})
}

func TestUsersPostgresRepository_List(t *testing.T) {
	repo := setupUsersRepoTest(t)
	ctx := context.Background()

	seed := func(name, email string, role domain.UserRole) *domain.User {
		created, err := repo.Create(ctx, domain.User{Name: name, Email: email, PasswordHash: "hash", Role: domain.RoleUser})
		require.NoError(t, err)
		if role != domain.RoleUser {
			created, err = repo.UpdateRole(ctx, created.UUID, role)
			require.NoError(t, err)
		}
		return created
	}
	alice := seed("Alice Admin", "alice@example.com", domain.RoleAdmin)
	bob := seed("Bob Builder", "bob@example.com", domain.RoleUser)
	carol := seed("Carol 100%", "carol_x@example.com", domain.RoleUser)

	t.Run("success - no filters returns newest first", func(t *testing.T) {
		users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		require.Len(t, users, 3)
		assert.Equal(t, []string{carol.UUID, bob.UUID, alice.UUID}, []string{users[0].UUID, users[1].UUID, users[2].UUID})
		assert.Equal(t, "alice@example.com", users[2].Email)
		assert.Equal(t, domain.RoleAdmin, users[2].Role)
	})

	t.Run("success - filter by role", func(t *testing.T) {
		role := domain.RoleAdmin

		users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Role: &role})

		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, users, 1)
		assert.Equal(t, alice.UUID, users[0].UUID)
	})

	t.Run("success - search matches email prefix case-insensitively", func(t *testing.T) {
		search := "BOB@"

		users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Search: &search})

		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, users, 1)
		assert.Equal(t, bob.UUID, users[0].UUID)
	})

	t.Run("success - search matches name prefix", func(t *testing.T) {
		search := "alice"

		users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Search: &search})

		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, users, 1)
		assert.Equal(t, alice.UUID, users[0].UUID)
	})

	t.Run("success - search treats LIKE wildcards literally", func(t *testing.T) {
		for search, want := range map[string]int{"%": 0, "_": 0, "carol_": 1, "Carol 100%": 1} {
			users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Search: &search})

			require.NoError(t, err)
			assert.Equal(t, int64(want), total, search)
			assert.Len(t, users, want, search)
		}
	})

	t.Run("success - cursor pages through results", func(t *testing.T) {
		first, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 2})
		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		require.Len(t, first, 2)

		cursor := first[1].UUID
		second, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 2, Cursor: &cursor})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		require.Len(t, second, 1)
		assert.Equal(t, alice.UUID, second[0].UUID)
	})

	t.Run("success - search with a literal backslash matches nothing", func(t *testing.T) {
		search := `\`

		users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Search: &search})

		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, users)
	})

	t.Run("success - role, search and cursor combined, including a deleted cursor row", func(t *testing.T) {
		dora1 := seed("Dora One", "dora1@example.com", domain.RoleAdmin)
		dora2 := seed("Dora Two", "dora2@example.com", domain.RoleAdmin)
		dora3 := seed("Dora Three", "dora3@example.com", domain.RoleAdmin)
		seed("Dora User", "dora4@example.com", domain.RoleUser)
		role := domain.RoleAdmin
		search := "dora"
		cursor := dora3.UUID
		require.NoError(t, repo.Delete(ctx, dora3.UUID))

		users, total, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Role: &role, Search: &search, Cursor: &cursor})

		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		require.Len(t, users, 2)
		assert.Equal(t, []string{dora2.UUID, dora1.UUID}, []string{users[0].UUID, users[1].UUID})
	})

	t.Run("error - invalid cursor", func(t *testing.T) {
		cursor := "not-a-uuid"

		users, _, err := repo.List(ctx, domain.ListUsersDTO{Limit: 10, Cursor: &cursor})

		assert.Nil(t, users)
		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "users.invalidCursor", validationErr.Error())
	})
}
