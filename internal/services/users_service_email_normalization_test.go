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

func TestDomainNormalizeEmail(t *testing.T) {
	assert.Equal(t, normalizedEmail, domain.NormalizeEmail(messyEmail))
	assert.Equal(t, "", domain.NormalizeEmail("   "))
}

func TestUsersService_EmailNormalization(t *testing.T) {
	t.Run("Create stores the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		emailVerification := new(mocks.EmailVerificationServiceMock)
		emailVerification.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil).Once()
		service := services.NewUserService(repo, emailVerification)
		repo.On("Create", mock.MatchedBy(func(u domain.User) bool { return u.Email == normalizedEmail })).
			Return(&domain.User{UUID: "uuid", Email: normalizedEmail}, nil).Once()

		_, err := service.Create(context.Background(), domain.CreateUserDTO{Name: "User", Email: messyEmail, Password: "password123"})

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("CreateOAuth stores the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
		repo.On("Create", mock.MatchedBy(func(u domain.User) bool { return u.Email == normalizedEmail })).
			Return(&domain.User{UUID: "uuid", Email: normalizedEmail}, nil).Once()

		_, err := service.CreateOAuth(context.Background(), domain.CreateOAuthUserDTO{Name: "User", Email: messyEmail})

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("GetByEmail looks up the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
		repo.On("FindByEmail", normalizedEmail).Return(&domain.User{UUID: "uuid", Email: normalizedEmail}, nil).Once()

		user, err := service.GetByEmail(context.Background(), messyEmail)

		require.NoError(t, err)
		assert.Equal(t, normalizedEmail, user.Email)
		repo.AssertExpectations(t)
	})

	t.Run("Update stores the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
		email := messyEmail
		repo.On("FindByUUID", "some-uuid").Return(&domain.User{UUID: "some-uuid", Email: "old@example.com"}, nil).Once()
		repo.On("Update", mock.MatchedBy(func(u domain.User) bool { return u.Email == normalizedEmail })).Return(nil).Once()

		err := service.Update(context.Background(), selfActor, "some-uuid", domain.UserUpdateDTO{Email: &email})

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("ResendVerification looks up the normalized email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		emailVerification := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, emailVerification)
		user := &domain.User{UUID: "uuid", Email: normalizedEmail}
		repo.On("FindByEmail", normalizedEmail).Return(user, nil).Once()
		emailVerification.On("SendVerificationEmail", mock.Anything, user).Return(nil).Once()

		err := service.ResendVerification(context.Background(), messyEmail)

		require.NoError(t, err)
		repo.AssertExpectations(t)
		emailVerification.AssertExpectations(t)
	})
}

func newAuthServiceOverRealUsers(repo *mocks.UsersRepositoryMock, authRepo *mocks.AuthRepositoryMock, registry *mocks.OAuthProviderRegistryMock, emailProvider *mocks.EmailProviderMock) domain.AuthService {
	tokens := services.NewTokenService(normalizationKey)
	emailVerification := services.NewEmailVerificationService(tokens, emailProvider, "https://app.test/verify-email")
	return services.NewAuthService(services.NewUserService(repo, emailVerification), authRepo, registry, newTransactorMock(), tokens, testSessionMaxAge)
}

func TestAuthService_EmailNormalization(t *testing.T) {
	t.Run("CredentialsLogin works with different casing and whitespace", func(t *testing.T) {
		hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
		require.NoError(t, err)
		repo := new(mocks.UsersRepositoryMock)
		repo.On("FindByEmail", normalizedEmail).Return(&domain.User{UUID: "uuid", Email: normalizedEmail, PasswordHash: string(hash), Role: domain.RoleUser}, nil).Once()
		repo.On("SetRefreshJTI", "uuid", mock.AnythingOfType("*string")).Return(nil).Once()
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
		service := newAuthServiceOverRealUsers(repo, authRepo, registry, new(mocks.EmailProviderMock))

		var stored domain.User
		repo.On("Create", mock.Anything).Run(func(args mock.Arguments) {
			stored = args.Get(0).(domain.User)
			stored.UUID = "local-uuid"
		}).Return(&domain.User{UUID: "local-uuid", Email: normalizedEmail}, nil).Once()
		emailVerification := new(mocks.EmailVerificationServiceMock)
		emailVerification.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil).Once()
		_, err := services.NewUserService(repo, emailVerification).Create(context.Background(), domain.CreateUserDTO{Name: "User", Email: messyEmail, Password: "password123"})
		require.NoError(t, err)
		require.Equal(t, normalizedEmail, stored.Email)

		repo.On("FindByEmail", normalizedEmail).Return(&domain.User{UUID: "local-uuid", Email: stored.Email, EmailVerified: true}, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		authRepo.On("CreateUserOAuthProvider", domain.UserOAuthProvider{
			UserUUID: "local-uuid", Provider: provider, ProviderUserID: providerUserID, ProviderEmail: normalizedEmail,
		}).Return(&domain.UserOAuthProvider{}, nil).Once()
		repo.On("SetRefreshJTI", "local-uuid", mock.AnythingOfType("*string")).Return(nil).Once()
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
	})
}
