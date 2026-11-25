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

func testOAuthLoginResolveUser(t *testing.T) {
	const (
		provider       = domain.OAuthProviderGoogle
		providerUserID = "provider-user-id"
		code           = "auth-code"
		nonce          = "browser-nonce"
		codeVerifier   = "code-verifier"
		email          = "user@example.com"
		userUUID       = "user-uuid"
		linkUUID       = "link-uuid"
	)

	providerNotFound := domain.NewNotFoundError("auth.oauthProvider.notFound")
	userNotFound := domain.NewNotFoundError("user.notFound")

	type fixture struct {
		service      domain.AuthService
		usersService *mocks.UsersServiceMock
		authRepo     *mocks.AuthRepositoryMock
		transactor   *mocks.TransactorMock
		pending      *mocks.PendingSignupServiceMock
		emails       *mocks.EmailVerificationServiceMock
		sessionsRepo *mocks.SessionsRepositoryMock
	}

	setup := func(t *testing.T, userInfo *domain.OAuthProviderUserInfo) fixture {
		t.Helper()
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		registry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		pending := new(mocks.PendingSignupServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		emails := new(mocks.EmailVerificationServiceMock)
		sessionsRepo.On("DeleteExpiredByUser", mock.Anything, mock.Anything).Return(nil).Maybe()
		sessionsRepo.On("Create", mock.Anything).Return(&domain.UserSession{UUID: "session-uuid"}, nil).Maybe()
		sessionsRepo.On("DeleteOldestBeyond", mock.Anything, mock.Anything).Return(nil).Maybe()
		providerMock := new(mocks.OAuthProviderMock)
		registry.On("Get", provider).Return(providerMock, nil)
		providerMock.On("GetUserInfo", mock.Anything, code, codeVerifier).Return(userInfo, nil)
		service := services.NewAuthService(usersService, pending, authRepo, sessionsRepo, registry, transactor, services.NewTokenService("test-secret-key", testClock), emails, testSessionMaxAge, testMaxSessions, testClock)
		return fixture{service, usersService, authRepo, transactor, pending, emails, sessionsRepo}
	}

	login := func(t *testing.T, f fixture) (*domain.OAuthLoginResult, error) {
		t.Helper()
		state, err := f.service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{"redirect_uri": "http://localhost:3000/callback", "nonce": nonce},
		})
		require.NoError(t, err)
		return f.service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})
	}

	t.Run("unverified provider email starts a pending signup and writes nothing", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			existing *domain.User
		}{
			{"no account with that email", nil},
			{"account with that email", &domain.User{UUID: userUUID, Email: email}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: "  User@Example.COM ", EmailVerified: false})
				f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
				f.pending.On("StartOAuth", domain.StartOAuthSignupDTO{Name: "User", Email: email, Provider: provider, ProviderUserID: providerUserID}).Return("pending-uuid", nil).Once()

				result, err := login(t, f)

				require.NoError(t, err)
				assert.Equal(t, "pending-uuid", result.PendingSignupUUID)
				assert.Equal(t, "http://localhost:3000/callback", result.RedirectURI)
				assert.Nil(t, result.User)
				assert.Empty(t, result.Tokens)
				f.usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
				f.authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
				f.pending.AssertExpectations(t)
			})
		}
	})

	t.Run("unverified provider email with a linked provider still signs in", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: false})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(&domain.UserOAuthProvider{UserUUID: userUUID}, nil).Once()
		f.usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		assert.Empty(t, result.PendingSignupUUID)
		f.pending.AssertNotCalled(t, "StartOAuth", mock.Anything)
	})

	t.Run("unverified provider email hitting the send limit reports verification limited", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: false})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.pending.On("StartOAuth", mock.Anything).Return("", domain.ErrEmailSendLimit).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.True(t, result.VerificationLimited)
		assert.Equal(t, "http://localhost:3000/callback", result.RedirectURI)
		assert.Empty(t, result.PendingSignupUUID)
	})

	t.Run("unverified provider email with another StartOAuth failure returns it", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: false})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		sendErr := domain.NewInternalServerError("auth.signup.sendFailed", errors.New("smtp"))
		f.pending.On("StartOAuth", mock.Anything).Return("", sendErr).Once()

		result, err := login(t, f)

		assert.Equal(t, sendErr, err)
		assert.Nil(t, result)
	})

	t.Run("Case 2 links within a transaction when the provider email is verified", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", domain.UserOAuthProvider{
			UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID, ProviderEmail: email,
		}).Return(&domain.UserOAuthProvider{UUID: linkUUID, Provider: provider}, nil).Once()
		f.emails.On("SendOAuthLinkedNotice", email, domain.OAuthLinkRevert{UserUUID: userUUID, LinkUUID: linkUUID, Provider: provider}).Return(nil).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		f.authRepo.AssertExpectations(t)
		f.emails.AssertExpectations(t)
		f.transactor.AssertNumberOfCalls(t, "WithinTx", 2)
	})

	t.Run("Case 2 still signs in when the link notice cannot be sent", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", mock.Anything).Return(&domain.UserOAuthProvider{UUID: linkUUID, Provider: provider}, nil).Once()
		f.emails.On("SendOAuthLinkedNotice", email, mock.Anything).Return(errors.New("smtp down")).Once()

		result, err := login(t, f)

		require.NoError(t, err)
		assert.Equal(t, userUUID, result.User.UUID)
		assert.NotEmpty(t, result.Tokens.AccessToken)
		f.emails.AssertExpectations(t)
	})

	t.Run("Case 2 sends the link notice after the session started", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", mock.Anything).Return(&domain.UserOAuthProvider{UUID: linkUUID, Provider: provider}, nil).Once()
		sessionStarted := false
		f.sessionsRepo.ExpectedCalls = nil
		f.sessionsRepo.On("DeleteExpiredByUser", mock.Anything, mock.Anything).Return(nil)
		f.sessionsRepo.On("DeleteOldestBeyond", mock.Anything, mock.Anything).Return(nil)
		f.sessionsRepo.On("Create", mock.Anything).Return(&domain.UserSession{UUID: "session-uuid"}, nil).Run(func(mock.Arguments) { sessionStarted = true })
		f.emails.On("SendOAuthLinkedNotice", email, mock.Anything).Return(nil).Once().Run(func(mock.Arguments) {
			assert.True(t, sessionStarted, "notice sent before the session started")
		})

		_, err := login(t, f)

		require.NoError(t, err)
		f.emails.AssertExpectations(t)
	})

	t.Run("Case 2 still notifies the owner when the session cannot start", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", mock.Anything).Return(&domain.UserOAuthProvider{UUID: linkUUID, Provider: provider}, nil).Once()
		f.sessionsRepo.ExpectedCalls = nil
		f.sessionsRepo.On("DeleteExpiredByUser", mock.Anything, mock.Anything).Return(nil)
		f.sessionsRepo.On("Create", mock.Anything).Return(nil, errors.New("db down"))
		f.emails.On("SendOAuthLinkedNotice", email, mock.Anything).Return(nil).Once()

		result, err := login(t, f)

		require.Error(t, err)
		assert.Nil(t, result)
		f.emails.AssertExpectations(t)
	})

	t.Run("no link notice when the provider is already linked (Case 1), a user is created (Case 3) or the email is unverified", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(&domain.UserOAuthProvider{UserUUID: userUUID}, nil).Once()
		f.usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		_, err := login(t, f)
		require.NoError(t, err)
		f.emails.AssertNotCalled(t, "SendOAuthLinkedNotice", mock.Anything, mock.Anything)

		f = setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(nil, userNotFound).Once()
		f.usersService.On("CreateOAuth", mock.Anything).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
		f.authRepo.On("CreateUserOAuthProvider", mock.Anything).Return(&domain.UserOAuthProvider{UUID: linkUUID, Provider: provider}, nil).Once()
		_, err = login(t, f)
		require.NoError(t, err)
		f.emails.AssertNotCalled(t, "SendOAuthLinkedNotice", mock.Anything, mock.Anything)

		f = setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: email, EmailVerified: false})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.pending.On("StartOAuth", mock.Anything).Return("pending-uuid", nil).Once()
		_, err = login(t, f)
		require.NoError(t, err)
		f.emails.AssertNotCalled(t, "SendOAuthLinkedNotice", mock.Anything, mock.Anything)
	})

	t.Run("normalizes the provider email before lookup, create and link", func(t *testing.T) {
		f := setup(t, &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: "  User@Example.COM ", EmailVerified: true})
		f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, providerNotFound).Once()
		f.usersService.On("GetByEmail", email).Return(nil, userNotFound).Once()
		f.usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: "User", Email: email}).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
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
		f.usersService.On("GetByEmail", email).Return(&domain.User{UUID: userUUID, Email: email}, nil).Once()
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
