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

func TestUsersPostgresRepository(t *testing.T) {
	if testing.Short() {
		t.Skip("TestUsersPostgresRepository: Skipping repository tests in short mode.")
	}

	ctx := context.Background()
	repo := repositories.NewUsersPostgresRepository(testDB)
	require.NotNil(t, repo)

	truncateTables(ctx, testDB)

	var createdUser *domain.User

	t.Run("Create", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			user := domain.User{
				Name:         "John Doe",
				Email:        "john.doe@example.com",
				PasswordHash: "hashed_password",
			}

			var err error
			createdUser, err = repo.Create(user)
			require.NoError(t, err)
			assert.NotEmpty(t, createdUser.UUID)
			assert.NotEqual(t, createdUser.CreatedAt, 0)
			assert.NotEqual(t, createdUser.UpdatedAt, 0)
			assert.Equal(t, user.Name, createdUser.Name)
			assert.Equal(t, user.Email, createdUser.Email)
			assert.Equal(t, user.PasswordHash, createdUser.PasswordHash)
		})

		t.Run("duplicate email", func(t *testing.T) {
			user := domain.User{
				Name:         "Jane Doe",
				Email:        "john.doe@example.com", // Same email
				PasswordHash: "another_password",
			}

			_, err := repo.Create(user)
			assert.Error(t, err)
		})
	})

	t.Run("FindByUUID", func(t *testing.T) {
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
	})

	t.Run("Update", func(t *testing.T) {
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
	})

	t.Run("Delete", func(t *testing.T) {
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
	})
}
