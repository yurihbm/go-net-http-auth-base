package repositories_test

import (
	"context"
	"errors"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type failingLinkAuthRepository struct {
	domain.AuthRepository
	err error
}

func (r failingLinkAuthRepository) CreateUserOAuthProvider(context.Context, domain.UserOAuthProvider) (*domain.UserOAuthProvider, error) {
	return nil, r.err
}

func TestOAuthLogin_Transaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const (
		provider       = domain.OAuthProviderGoogle
		providerUserID = "google-user-123"
		code           = "auth-code"
		email          = "new-oauth@example.com"
	)

	setup := func(t *testing.T, linkErr error) (domain.AuthService, domain.UsersRepository, domain.AuthRepository, string) {
		t.Helper()
		truncateTables(context.Background(), testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		authRepo := repositories.NewAuthPostgresRepository(db)

		var serviceAuthRepo domain.AuthRepository = authRepo
		if linkErr != nil {
			serviceAuthRepo = failingLinkAuthRepository{AuthRepository: authRepo, err: linkErr}
		}

		providerMock := new(mocks.OAuthProviderMock)
		providerMock.On("GetUserInfo", mock.Anything, code).Return(&domain.OAuthProviderUserInfo{
			ID:            providerUserID,
			Name:          "New OAuth User",
			Email:         email,
			EmailVerified: true,
		}, nil)
		registry := new(mocks.OAuthProviderRegistryMock)
		registry.On("Get", provider).Return(providerMock, nil)

		service := services.NewAuthService(
			services.NewUserService(usersRepo),
			serviceAuthRepo,
			registry,
			repositories.NewPostgresTransactor(testDB),
			"test-secret-key",
		)

		state, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{"redirect_uri": "http://localhost:3000/callback"},
		})
		require.NoError(t, err)

		return service, usersRepo, authRepo, state
	}

	t.Run("creates the user and links the provider", func(t *testing.T) {
		service, usersRepo, authRepo, state := setup(t, nil)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NoError(t, err)
		created, err := usersRepo.FindByEmail(context.Background(), email)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, result.User.UUID)
		linked, err := authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, linked.UserUUID)
	})

	t.Run("leaves no orphaned user when linking fails", func(t *testing.T) {
		linkErr := errors.New("link failed")
		service, usersRepo, _, state := setup(t, linkErr)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		assert.Equal(t, linkErr, err)
		assert.Nil(t, result)
		_, err = usersRepo.FindByEmail(context.Background(), email)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})
}
