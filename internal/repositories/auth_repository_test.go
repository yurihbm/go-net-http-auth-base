package repositories_test

import (
	"context"
	"errors"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuthRepoTest(t *testing.T) (domain.AuthRepository, domain.UsersRepository, *domain.User) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	ctx := context.Background()
	repo := repositories.NewAuthPostgresRepository(testDB)
	require.NotNil(t, repo)

	usersRepo := repositories.NewUsersPostgresRepository(testDB)
	require.NotNil(t, usersRepo)

	truncateTables(ctx, testDB)

	// Create a test user first
	user := domain.User{
		Name:         "Test User",
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
	}

	createdUser, err := usersRepo.Create(user)
	require.NoError(t, err)
	require.NotNil(t, createdUser)

	return repo, usersRepo, createdUser
}

func TestAuthPostgresRepository_CreateUserOAuthProvider(t *testing.T) {
	repo, _, createdUser := setupAuthRepoTest(t)

	t.Run("success", func(t *testing.T) {
		provider := domain.UserOAuthProvider{
			UserUUID:       createdUser.UUID,
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google_user_123",
			ProviderEmail:  "test@gmail.com",
		}

		createdProvider, err := repo.CreateUserOAuthProvider(provider)
		require.NoError(t, err)
		require.NotNil(t, createdProvider)
		assert.NotEmpty(t, createdProvider.UUID)
		assert.Equal(t, createdUser.UUID, createdProvider.UserUUID)
		assert.Equal(t, domain.OAuthProviderGoogle, createdProvider.Provider)
		assert.Equal(t, "google_user_123", createdProvider.ProviderUserID)
		assert.Equal(t, "test@gmail.com", createdProvider.ProviderEmail)
		assert.NotEqual(t, createdProvider.CreatedAt, 0)
	})

	t.Run("conflict", func(t *testing.T) {
		provider := domain.UserOAuthProvider{
			UserUUID:       createdUser.UUID,
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google_user_conflict",
			ProviderEmail:  "conflict@gmail.com",
		}

		_, err := repo.CreateUserOAuthProvider(provider)
		require.NoError(t, err)

		_, err = repo.CreateUserOAuthProvider(provider)
		require.Error(t, err)
		var conflictErr *domain.ConflictError
		assert.True(t, errors.As(err, &conflictErr))
	})

	t.Run("invalid user uuid", func(t *testing.T) {
		provider := domain.UserOAuthProvider{
			UserUUID:       "invalid-uuid",
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google_user_456",
			ProviderEmail:  "test2@gmail.com",
		}

		_, err := repo.CreateUserOAuthProvider(provider)
		require.Error(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})

	t.Run("user not found (fk violation)", func(t *testing.T) {
		// Use a valid UUID but one that doesn't exist in the DB
		nonExistentUserUUID := uuid.New().String()
		provider := domain.UserOAuthProvider{
			UserUUID:       nonExistentUserUUID,
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google_user_999",
			ProviderEmail:  "test999@gmail.com",
		}

		_, err := repo.CreateUserOAuthProvider(provider)
		require.Error(t, err)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
		assert.Equal(t, "auth.user.notFound", notFoundErr.Error())
	})
}

func TestAuthPostgresRepository_GetUserOAuthProviderByProviderAndProviderUserID(t *testing.T) {
	repo, _, createdUser := setupAuthRepoTest(t)

	// Setup data
	provider := domain.UserOAuthProvider{
		UserUUID:       createdUser.UUID,
		Provider:       domain.OAuthProviderGoogle,
		ProviderUserID: "google_user_123",
		ProviderEmail:  "test@gmail.com",
	}
	createdProvider, err := repo.CreateUserOAuthProvider(provider)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		foundProvider, err := repo.GetUserOAuthProviderByProviderAndProviderUserID(
			domain.OAuthProviderGoogle,
			"google_user_123",
		)
		require.NoError(t, err)
		require.NotNil(t, foundProvider)
		assert.Equal(t, createdProvider.UUID, foundProvider.UUID)
		assert.Equal(t, createdUser.UUID, foundProvider.UserUUID)
		assert.Equal(t, domain.OAuthProviderGoogle, foundProvider.Provider)
		assert.Equal(t, "google_user_123", foundProvider.ProviderUserID)
		assert.Equal(t, "test@gmail.com", foundProvider.ProviderEmail)
	})

	t.Run("not found", func(t *testing.T) {
		foundProvider, err := repo.GetUserOAuthProviderByProviderAndProviderUserID(
			domain.OAuthProviderGoogle,
			"nonexistent_user_id",
		)
		require.Error(t, err)
		assert.Nil(t, foundProvider)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})
}

func TestAuthPostgresRepository_ListUserOAuthProvidersByUserUUID(t *testing.T) {
	repo, _, createdUser := setupAuthRepoTest(t)

	// Setup initial provider
	provider := domain.UserOAuthProvider{
		UserUUID:       createdUser.UUID,
		Provider:       domain.OAuthProviderGoogle,
		ProviderUserID: "google_user_123",
		ProviderEmail:  "test@gmail.com",
	}
	createdProvider, err := repo.CreateUserOAuthProvider(provider)
	require.NoError(t, err)

	t.Run("success with one provider", func(t *testing.T) {
		providers, err := repo.ListUserOAuthProvidersByUserUUID(createdUser.UUID)
		require.NoError(t, err)
		require.NotNil(t, providers)
		assert.Equal(t, 1, len(providers))
		assert.Equal(t, createdProvider.UUID, providers[0].UUID)
		assert.Equal(t, createdUser.UUID, providers[0].UserUUID)
	})

	t.Run("success with multiple providers", func(t *testing.T) {
		// Add another provider for the same user
		provider2 := domain.UserOAuthProvider{
			UserUUID:       createdUser.UUID,
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google_user_789",
			ProviderEmail:  "test3@gmail.com",
		}

		_, err := repo.CreateUserOAuthProvider(provider2)
		require.NoError(t, err)

		providers, err := repo.ListUserOAuthProvidersByUserUUID(createdUser.UUID)
		require.NoError(t, err)
		require.NotNil(t, providers)
		assert.Equal(t, 2, len(providers))
	})

	t.Run("not found", func(t *testing.T) {
		nonExistentUserUUID := uuid.New().String()
		providers, err := repo.ListUserOAuthProvidersByUserUUID(nonExistentUserUUID)
		require.NoError(t, err)
		assert.Empty(t, providers)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		_, err := repo.ListUserOAuthProvidersByUserUUID("invalid-uuid")
		require.Error(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}

func TestAuthPostgresRepository_DeleteUserOAuthProvider(t *testing.T) {
	repo, _, createdUser := setupAuthRepoTest(t)

	t.Run("success", func(t *testing.T) {
		// Create a provider to delete
		provider := domain.UserOAuthProvider{
			UserUUID:       createdUser.UUID,
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google_user_delete_test",
			ProviderEmail:  "delete@gmail.com",
		}

		providerToDelete, err := repo.CreateUserOAuthProvider(provider)
		require.NoError(t, err)

		err = repo.DeleteUserOAuthProvider(providerToDelete.UUID)
		require.NoError(t, err)

		// Verify it's deleted
		providers, err := repo.ListUserOAuthProvidersByUserUUID(createdUser.UUID)
		require.NoError(t, err)

		for _, p := range providers {
			assert.NotEqual(t, providerToDelete.UUID, p.UUID)
		}
	})

	t.Run("idempotent delete", func(t *testing.T) {
		// Deleting a non-existent UUID should not return an error
		err := repo.DeleteUserOAuthProvider(uuid.New().String())
		assert.NoError(t, err)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		err := repo.DeleteUserOAuthProvider("invalid-uuid")
		require.Error(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
	})
}
