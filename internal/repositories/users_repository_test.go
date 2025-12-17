package repositories_test

import (
	"context"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"
	"testing"

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
	}

	createdUser, err := repo.Create(user)
	require.NoError(t, err)
	require.NotNil(t, createdUser)

	return createdUser
}

func TestUsersPostgresRepository_Create(t *testing.T) {
	repo := setupUsersRepoTest(t)

	t.Run("success", func(t *testing.T) {
		user := domain.User{
			Name:         "John Doe",
			Email:        "john.doe@example.com",
			PasswordHash: "hashed_password",
		}

		createdUser, err := repo.Create(user)
		require.NoError(t, err)
		assert.NotEmpty(t, createdUser.UUID)
		assert.NotEqual(t, createdUser.CreatedAt, 0)
		assert.NotEqual(t, createdUser.UpdatedAt, 0)
		assert.Equal(t, user.Name, createdUser.Name)
		assert.Equal(t, user.Email, createdUser.Email)
		assert.Equal(t, user.PasswordHash, createdUser.PasswordHash)
	})

	t.Run("duplicate email", func(t *testing.T) {
		// Create first user
		user1 := domain.User{
			Name:         "John Doe",
			Email:        "john.doe@example.com",
			PasswordHash: "hashed_password",
		}
		_, err := repo.Create(user1)
		require.NoError(t, err)

		// Try to create second user with same email
		user2 := domain.User{
			Name:         "Jane Doe",
			Email:        "john.doe@example.com", // Same email
			PasswordHash: "another_password",
		}

		_, err = repo.Create(user2)
		assert.Error(t, err)
	})
}

func TestUsersPostgresRepository_FindByUUID(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		foundUser, err := repo.FindByUUID(createdUser.UUID)
		require.NoError(t, err)
		require.NotNil(t, foundUser)
		assert.Equal(t, createdUser.UUID, foundUser.UUID)
		assert.Equal(t, createdUser.Name, foundUser.Name)
		assert.Equal(t, createdUser.Email, foundUser.Email)
	})

	t.Run("not found", func(t *testing.T) {
		nonExistentUUID := uuid.New().String()
		user, err := repo.FindByUUID(nonExistentUUID)
		assert.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		user, err := repo.FindByUUID("invalid-uuid")
		assert.Error(t, err)
		assert.Nil(t, user)
	})
}

func TestUsersPostgresRepository_FindByEmail(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		foundUser, err := repo.FindByEmail(createdUser.Email)
		require.NoError(t, err)
		require.NotNil(t, foundUser)
		assert.Equal(t, createdUser.UUID, foundUser.UUID)
		assert.Equal(t, createdUser.Name, foundUser.Name)
		assert.Equal(t, createdUser.Email, foundUser.Email)
	})

	t.Run("not found", func(t *testing.T) {
		user, err := repo.FindByEmail("nonexistent@example.com")
		assert.Error(t, err)
		assert.Nil(t, user)
	})
}

func TestUsersPostgresRepository_Update(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		createdUser.Name = "John Doe Updated"
		createdUser.Email = "john.doe.updated@example.com"

		err := repo.Update(*createdUser)
		require.NoError(t, err)

		updatedUser, err := repo.FindByUUID(createdUser.UUID)
		require.NoError(t, err)
		require.NotNil(t, updatedUser)
		assert.Equal(t, "John Doe Updated", updatedUser.Name)
		assert.Equal(t, "john.doe.updated@example.com", updatedUser.Email)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		invalidUser := domain.User{UUID: "invalid"}
		err := repo.Update(invalidUser)
		assert.Error(t, err)
	})
}

func TestUsersPostgresRepository_Delete(t *testing.T) {
	repo := setupUsersRepoTest(t)
	createdUser := seedUser(t, repo)

	t.Run("success", func(t *testing.T) {
		err := repo.Delete(createdUser.UUID)
		require.NoError(t, err)

		deletedUser, err := repo.FindByUUID(createdUser.UUID)
		assert.Error(t, err)
		assert.Nil(t, deletedUser)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		err := repo.Delete("invalid-uuid")
		assert.Error(t, err)
	})
}
