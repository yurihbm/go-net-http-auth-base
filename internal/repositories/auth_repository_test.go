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

func TestAuthPostgresRepository(t *testing.T) {
	if testing.Short() {
		t.Skip("TestAuthPostgresRepository: Skipping repository tests in short mode.")
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

	var createdProvider *domain.UserOAuthProvider

	t.Run("CreateUserOAuthProvider", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			provider := domain.UserOAuthProvider{
				UserUUID:       createdUser.UUID,
				Provider:       domain.OAuthProviderGoogle,
				ProviderUserID: "google_user_123",
				ProviderEmail:  "test@gmail.com",
			}

			var err error
			createdProvider, err = repo.CreateUserOAuthProvider(provider)
			require.NoError(t, err)
			require.NotNil(t, createdProvider)
			assert.NotEmpty(t, createdProvider.UUID)
			assert.Equal(t, createdUser.UUID, createdProvider.UserUUID)
			assert.Equal(t, domain.OAuthProviderGoogle, createdProvider.Provider)
			assert.Equal(t, "google_user_123", createdProvider.ProviderUserID)
			assert.Equal(t, "test@gmail.com", createdProvider.ProviderEmail)
			assert.NotEqual(t, createdProvider.CreatedAt, 0)
		})

		t.Run("invalid user uuid", func(t *testing.T) {
			provider := domain.UserOAuthProvider{
				UserUUID:       "invalid-uuid",
				Provider:       domain.OAuthProviderGoogle,
				ProviderUserID: "google_user_456",
				ProviderEmail:  "test2@gmail.com",
			}

			_, err := repo.CreateUserOAuthProvider(provider)
			assert.Error(t, err)
		})
	})

	t.Run("GetUserOAuthProviderByProviderAndProviderUserID", func(t *testing.T) {
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
			assert.Error(t, err)
			assert.Nil(t, foundProvider)
		})
	})

	t.Run("ListUserOAuthProvidersByUserUUID", func(t *testing.T) {
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
			assert.Error(t, err)
		})
	})

	t.Run("DeleteUserOAuthProvider", func(t *testing.T) {
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

		t.Run("invalid uuid", func(t *testing.T) {
			err := repo.DeleteUserOAuthProvider("invalid-uuid")
			assert.Error(t, err)
		})
	})
}
