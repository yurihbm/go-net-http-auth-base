package services_test

import (
	"context"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	messyEmail       = "  User@Example.COM "
	normalizedEmail  = "user@example.com"
	normalizationKey = "test-secret-key"
)

func TestUsersService_EmailNormalization(t *testing.T) {
	t.Run("Create stores the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock())
		repo.On("IsEmailReserved", mock.Anything).Return(false, nil).Maybe()
		repo.On("Create", mock.MatchedBy(func(u domain.User) bool { return u.Email == normalizedEmail })).
			Return(&domain.User{UUID: "uuid", Email: normalizedEmail}, nil).Once()

		_, err := service.Create(context.Background(), domain.NewUserDTO{Name: "User", Email: messyEmail, PasswordHash: "hash"})

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("CreateOAuth stores the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock())
		repo.On("IsEmailReserved", mock.Anything).Return(false, nil).Maybe()
		repo.On("Create", mock.MatchedBy(func(u domain.User) bool { return u.Email == normalizedEmail })).
			Return(&domain.User{UUID: "uuid", Email: normalizedEmail}, nil).Once()

		_, err := service.CreateOAuth(context.Background(), domain.CreateOAuthUserDTO{Name: "User", Email: messyEmail})

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("GetByEmail looks up the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock())
		repo.On("FindByEmail", normalizedEmail).Return(&domain.User{UUID: "uuid", Email: normalizedEmail}, nil).Once()

		user, err := service.GetByEmail(context.Background(), messyEmail)

		require.NoError(t, err)
		assert.Equal(t, normalizedEmail, user.Email)
		repo.AssertExpectations(t)
	})
}

func newAuthServiceOverRealUsers(repo *mocks.UsersRepositoryMock, authRepo *mocks.AuthRepositoryMock, registry *mocks.OAuthProviderRegistryMock, emailProvider *mocks.EmailProviderMock) domain.AuthService {
	tokens := services.NewTokenService(normalizationKey)
	sessionsRepo := new(mocks.SessionsRepositoryMock)
	sessionsRepo.On("DeleteExpiredByUser", mock.Anything, mock.Anything).Return(nil)
	sessionsRepo.On("Create", mock.Anything).Return(&domain.UserSession{UUID: "session-uuid"}, nil)
	sessionsRepo.On("DeleteOldestBeyond", mock.Anything, mock.Anything).Return(nil)
	return services.NewAuthService(services.NewUserService(repo, newTransactorMock()), nil, authRepo, sessionsRepo, registry, newTransactorMock(), tokens, services.NewEmailVerificationService(tokens, emailProvider, "https://app.test/revert-email-change", "https://app.test/revert-oauth-link"), testSessionMaxAge, testMaxSessions)
}

func TestAuthService_EmailNormalization(t *testing.T) {
	t.Run("CredentialsLogin works with different casing and whitespace", func(t *testing.T) {
		hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
		require.NoError(t, err)
		repo := new(mocks.UsersRepositoryMock)
		repo.On("FindByEmail", normalizedEmail).Return(&domain.User{UUID: "uuid", Email: normalizedEmail, PasswordHash: string(hash), Role: domain.RoleUser}, nil).Once()
		service := newAuthServiceOverRealUsers(repo, new(mocks.AuthRepositoryMock), new(mocks.OAuthProviderRegistryMock), new(mocks.EmailProviderMock))

		tokens, err := service.CredentialsLogin(context.Background(), domain.CredentialsLoginDTO{Email: messyEmail, Password: "password123"})

		require.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		repo.AssertExpectations(t)
	})

	t.Run("OAuthLogin matches a mixed-case local account instead of creating a duplicate", func(t *testing.T) {
		const (
			provider       = domain.OAuthProviderGoogle
			providerUserID = "provider-user-id"
			code           = "auth-code"
			nonce          = "browser-nonce"
			codeVerifier   = "code-verifier"
		)
		repo := new(mocks.UsersRepositoryMock)
		authRepo := new(mocks.AuthRepositoryMock)
		registry := new(mocks.OAuthProviderRegistryMock)
		providerMock := new(mocks.OAuthProviderMock)
		registry.On("Get", provider).Return(providerMock, nil)
		providerMock.On("GetUserInfo", mock.Anything, code, codeVerifier).
			Return(&domain.OAuthProviderUserInfo{ID: providerUserID, Name: "User", Email: normalizedEmail, EmailVerified: true}, nil)
		emailProvider := new(mocks.EmailProviderMock)
		emailProvider.On("Send", mock.Anything, mock.MatchedBy(func(msg domain.EmailMessage) bool { return msg.To == normalizedEmail })).Return(nil).Once()
		service := newAuthServiceOverRealUsers(repo, authRepo, registry, emailProvider)

		var stored domain.User
		repo.On("IsEmailReserved", mock.Anything).Return(false, nil).Maybe()
		repo.On("Create", mock.Anything).Run(func(args mock.Arguments) {
			stored = args.Get(0).(domain.User)
			stored.UUID = "local-uuid"
		}).Return(&domain.User{UUID: "local-uuid", Email: normalizedEmail}, nil).Once()
		_, err := services.NewUserService(repo, newTransactorMock()).Create(context.Background(), domain.NewUserDTO{Name: "User", Email: messyEmail, PasswordHash: "hash"})
		require.NoError(t, err)
		require.Equal(t, normalizedEmail, stored.Email)

		repo.On("FindByEmail", normalizedEmail).Return(&domain.User{UUID: "local-uuid", Email: stored.Email}, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		authRepo.On("CreateUserOAuthProvider", domain.UserOAuthProvider{
			UserUUID: "local-uuid", Provider: provider, ProviderUserID: providerUserID, ProviderEmail: normalizedEmail,
		}).Return(&domain.UserOAuthProvider{UUID: "link-uuid", Provider: provider}, nil).Once()
		state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{"redirect_uri": "http://localhost:3000/callback", "nonce": nonce},
		})
		require.NoError(t, err)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		assert.Equal(t, "local-uuid", result.User.UUID)
		repo.AssertNumberOfCalls(t, "Create", 1)
		authRepo.AssertExpectations(t)
		emailProvider.AssertExpectations(t)
	})
}
