package services_test

import (
	"context"
	"errors"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuthService_OAuthLogin_ResolveUser(t *testing.T) {
	const (
		provider       = domain.OAuthProviderGoogle
		providerUserID = "provider-user-id"
		code           = "auth-code"
		nonce          = "browser-nonce"
		codeVerifier   = "code-verifier"
		email          = "user@example.com"
		userUUID       = "user-uuid"
	)

	providerNotFound := domain.NewNotFoundError("auth.oauthProvider.notFound")
	userNotFound := domain.NewNotFoundError("user.notFound")

	type fixture struct {
		service      domain.AuthService
		usersService *mocks.UsersServiceMock
		authRepo     *mocks.AuthRepositoryMock
		transactor   *mocks.TransactorMock
	}

	setup := func(t *testing.T, userInfo *domain.OAuthProviderUserInfo) fixture {
		t.Helper()
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		registry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		sessionsRepo.On("DeleteExpiredByUser", mock.Anything, mock.Anything).Return(nil).Maybe()
		sessionsRepo.On("Create", mock.Anything).Return(&domain.UserSession{UUID: "session-uuid"}, nil).Maybe()
		sessionsRepo.On("DeleteOldestBeyond", mock.Anything, mock.Anything).Return(nil).Maybe()
		providerMock := new(mocks.OAuthProviderMock)
		registry.On("Get", provider).Return(providerMock, nil)
		providerMock.On("GetUserInfo", mock.Anything, code, codeVerifier).Return(userInfo, nil)
		service := services.NewAuthService(usersService, authRepo, sessionsRepo, registry, transactor, services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
		return fixture{service, usersService, authRepo, transactor}
	}

	login := func(t *testing.T, f fixture) (*domain.OAuthLoginResult, error) {
		t.Helper()
		state, err := f.service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{"redirect_uri": "http://localhost:3000/callback", "nonce": nonce},
		})
		require.NoError(t, err)
		return f.service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})
	}

	t.Run("Case 3 refuses an unverified provider email", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: false})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(nil, userNotFound).Once()

		result, err := login(t, f)

		var validationErr *domain.ValidationError
		require.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.emailNotVerified", err.Error())
		assert.Nil(t, result)
		f.usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
		f.authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
	})

	t.Run("Case 2 refuses linking to an unverified local account", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email, EmailVerified: false}, nil).Once()

		result, err := login(t, f)

		var validationErr *domain.ValidationError
		require.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.localEmailNotVerified", err.Error())
		assert.Nil(t, result)
		f.authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
		f.usersService.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Case 2 links within a transaction when both emails are verified", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email, EmailVerified: true}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", domain.UserOAuthProvider{
			UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID, ProviderEmail: email,
		}).Return(&domain.UserOAuthProvider{}, nil).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		f.authRepo.AssertExpectations(t)
		f.transactor.AssertNumberOfCalls(t, "WithinTx", 2)
	})

	t.Run("normalizes the provider email before lookup, create and link", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: "  User@Example.COM ", EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(nil, userNotFound).Once()
		f.usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: "User", Email: email, EmailVerified: true}).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", domain.UserOAuthProvider{
			UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID, ProviderEmail: email,
		}).Return(&domain.UserOAuthProvider{}, nil).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		f.usersService.AssertExpectations(t)
		f.authRepo.AssertExpectations(t)
	})

	t.Run("rejects a provider email that is blank after trimming", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: "   ", EmailVerified: true})

		result, err := login(t, f)

		var validationErr *domain.ValidationError
		require.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.invalidUserInfo", err.Error())
		assert.Nil(t, result)
		f.authRepo.AssertNotCalled(t, "GetUserOAuthProviderByProviderAndProviderUserID", mock.Anything, mock.Anything)
	})

	t.Run("re-resolves to the existing user when a concurrent callback created it", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(nil, userNotFound).Once()
		f.usersService.On("CreateOAuth", mock.Anything).Return(nil, domain.NewConflictError("users.email.conflict")).Once()
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(&domain.UserOAuthProvider{UserUUID: userUUID}, nil).Once()
		f.usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		f.usersService.AssertExpectations(t)
		f.authRepo.AssertExpectations(t)
		f.transactor.AssertNumberOfCalls(t, "WithinTx", 3)
	})

	t.Run("re-resolves to the existing link when a replayed callback linked it first", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email, EmailVerified: true}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", mock.Anything).Return(nil, domain.NewConflictError("auth.oauthProvider.conflict")).Once()
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(&domain.UserOAuthProvider{UserUUID: userUUID}, nil).Once()
		f.usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		f.transactor.AssertNumberOfCalls(t, "WithinTx", 3)
	})

	t.Run("returns the conflict when re-resolving conflicts again", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		conflictErr := domain.NewConflictError("users.email.conflict")
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Twice()
		f.usersService.On("GetByEmail", email).Return(nil, userNotFound).Twice()
		f.usersService.On("CreateOAuth", mock.Anything).Return(nil, conflictErr).Twice()

		result, err := login(t, f)

		assert.Equal(t, conflictErr, err)
		assert.Nil(t, result)
		f.transactor.AssertNumberOfCalls(t, "WithinTx", 2)
	})

	t.Run("does not swallow provider lookup errors", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		lookupErr := errors.New("db error")
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, lookupErr).Once()

		result, err := login(t, f)

		assert.Equal(t, lookupErr, err)
		assert.Nil(t, result)
		f.usersService.AssertNotCalled(t, "GetByEmail", mock.Anything)
	})

	t.Run("does not swallow user lookup errors", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		lookupErr := errors.New("db error")
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(nil, lookupErr).Once()

		result, err := login(t, f)

		assert.Equal(t, lookupErr, err)
		assert.Nil(t, result)
		f.usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
	})
}
