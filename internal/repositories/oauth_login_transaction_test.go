package repositories_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
		providerEmail  = "  New-OAuth@Example.COM "
		email          = "new-oauth@example.com"
		nonce          = "browser-nonce"
		codeVerifier   = "code-verifier"
	)

	setup := func(t *testing.T, linkErr error) (domain.AuthService, domain.UsersRepository, domain.AuthRepository, string) {
		t.Helper()
		truncateTables(context.Background(), testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		authRepo := repositories.NewAuthPostgresRepository(db)

		serviceAuthRepo := authRepo
		if linkErr != nil {
			serviceAuthRepo = failingLinkAuthRepository{AuthRepository: authRepo, err: linkErr}
		}

		providerMock := new(mocks.OAuthProviderMock)
		providerMock.On("GetUserInfo", mock.Anything, code, codeVerifier).Return(&domain.OAuthProviderUserInfo{
			ID:            providerUserID,
			Name:          "New OAuth User",
			Email:         providerEmail,
			EmailVerified: true,
		}, nil)
		registry := new(mocks.OAuthProviderRegistryMock)
		registry.On("Get", provider).Return(providerMock, nil)

		service := services.NewAuthService(
			services.NewUserService(usersRepo, new(mocks.EmailVerificationServiceMock)),
			serviceAuthRepo,
			registry,
			repositories.NewPostgresTransactor(testDB),
			services.NewTokenService("test-secret-key"),
			30*24*time.Hour,
		)

		state, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{"redirect_uri": "http://localhost:3000/callback", "nonce": nonce},
		})
		require.NoError(t, err)

		return service, usersRepo, authRepo, state
	}

	t.Run("creates the user and links the provider", func(t *testing.T) {
		service, usersRepo, authRepo, state := setup(t, nil)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		created, err := usersRepo.FindByEmail(context.Background(), email)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, result.User.UUID)
		assert.True(t, created.EmailVerified)
		linked, err := authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, linked.UserUUID)
		assert.Equal(t, email, linked.ProviderEmail)
	})

	t.Run("concurrent callbacks resolve to a single user", func(t *testing.T) {
		service, _, _, state := setup(t, nil)

		const callbacks = 5
		results := make([]*domain.OAuthLoginResult, callbacks)
		errs := make([]error, callbacks)
		var wg sync.WaitGroup
		for i := range callbacks {
			wg.Go(func() {
				results[i], errs[i] = service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})
			})
		}
		wg.Wait()

		for i := range callbacks {
			require.NoError(t, errs[i])
			assert.Equal(t, results[0].User.UUID, results[i].User.UUID)
		}
		var users, links int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&users))
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM user_oauth_providers").Scan(&links))
		assert.Equal(t, 1, users)
		assert.Equal(t, 1, links)
	})

	t.Run("refuses to link an unverified local account", func(t *testing.T) {
		service, usersRepo, authRepo, state := setup(t, nil)
		_, err := usersRepo.Create(context.Background(), domain.User{Name: "Squatter", Email: email, Role: domain.RoleUser})
		require.NoError(t, err)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		assert.Equal(t, "auth.providerCallback.localEmailNotVerified", err.Error())
		assert.Nil(t, result)
		_, err = authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("leaves no orphaned user when linking fails", func(t *testing.T) {
		linkErr := errors.New("link failed")
		service, usersRepo, _, state := setup(t, linkErr)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		assert.Equal(t, linkErr, err)
		assert.Nil(t, result)
		_, err = usersRepo.FindByEmail(context.Background(), email)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})
}
