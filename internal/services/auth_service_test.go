package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestNewAuthService(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")
	assert.NotNil(t, service)
}

func TestAuthService_CredentialsLogin(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			UUID:         "user-uuid-123",
			Name:         "Test User",
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
		}

		dto := domain.CredentialsLoginDTO{
			Email:    "test@example.com",
			Password: password,
		}

		usersService.On("GetByEmail", dto.Email).Return(user, nil).Once()

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		usersService.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		dto := domain.CredentialsLoginDTO{
			Email:    "notfound@example.com",
			Password: "password123",
		}

		usersService.On("GetByEmail", dto.Email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		require.NotNil(t, err)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
		assert.Equal(t, "auth.authenticate.invalidCredentials", err.Error())
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
		usersService.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		dto := domain.CredentialsLoginDTO{
			Email:    "test@example.com",
			Password: "password123",
		}

		usersService.On("GetByEmail", dto.Email).Return(nil, errors.New("db error")).Once()

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		require.NotNil(t, err)
		var internalServerErr *domain.InternalServerError
		assert.True(t, errors.As(err, &internalServerErr))
		assert.Equal(t, "auth.authenticate.userFetchFailed", err.Error())
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
		usersService.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
		user := &domain.User{
			UUID:         "user-uuid-123",
			Name:         "Test User",
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
		}

		dto := domain.CredentialsLoginDTO{
			Email:    "test@example.com",
			Password: "wrong-password",
		}

		usersService.On("GetByEmail", dto.Email).Return(user, nil).Once()

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		require.NotNil(t, err)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
		assert.Equal(t, "auth.authenticate.invalidCredentials", err.Error())
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
		usersService.AssertExpectations(t)
	})
}

func TestAuthService_VerifyToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceAccess,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("test-secret-key"))

		dto := domain.VerifyTokenDTO{
			Token:    tokenString,
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, userUUID, result.Subject)
	})

	t.Run("expired token", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceAccess,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("test-secret-key"))

		dto := domain.VerifyTokenDTO{
			Token:    tokenString,
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid token format", func(t *testing.T) {
		dto := domain.VerifyTokenDTO{
			Token:    "invalid-token",
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("token with wrong signing method", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceAccess,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

		dto := domain.VerifyTokenDTO{
			Token:    tokenString,
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("token signed with different secret", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceAccess,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("different-secret-key"))

		dto := domain.VerifyTokenDTO{
			Token:    tokenString,
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("wrong audience", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceRefresh,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("test-secret-key"))

		dto := domain.VerifyTokenDTO{
			Token:    tokenString,
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("token with missing or malformed claims", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		cases := map[string]jwt.MapClaims{
			"missing sub": {"aud": domain.TokenAudienceAccess, "exp": exp},
			"missing aud": {"sub": "user-uuid-123", "exp": exp},
			"missing exp": {"sub": "user-uuid-123", "aud": domain.TokenAudienceAccess},
			"wrong exp type": {
				"sub": "user-uuid-123",
				"aud": domain.TokenAudienceAccess,
				"exp": "tomorrow",
			},
		}

		for name, claims := range cases {
			t.Run(name, func(t *testing.T) {
				tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret-key"))
				require.NoError(t, err)

				result, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
					Token:    tokenString,
					Audience: domain.TokenAudienceAccess,
				})

				assert.Equal(t, services.ErrInvalidToken, err)
				assert.Nil(t, result)
			})
		}
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 24 * 7).Unix(),
			"aud": domain.TokenAudienceRefresh,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		refreshTokenString, _ := token.SignedString([]byte("test-secret-key"))

		dto := domain.RefreshTokenDTO{
			RefreshToken: refreshTokenString,
		}
		tokens, err := service.RefreshToken(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)

		// Verify the new access token contains the correct user UUID
		verifyDTO := domain.VerifyTokenDTO{
			Token:    tokens.AccessToken,
			Audience: domain.TokenAudienceAccess,
		}
		verifiedToken, err := service.VerifyToken(context.Background(), verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, userUUID, verifiedToken.Subject)

		// Verify the new refresh token contains the correct user UUID
		verifyDTO = domain.VerifyTokenDTO{
			Token:    tokens.RefreshToken,
			Audience: domain.TokenAudienceRefresh,
		}
		verifiedToken, err = service.VerifyToken(context.Background(), verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, userUUID, verifiedToken.Subject)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		dto := domain.RefreshTokenDTO{
			RefreshToken: "invalid-token",
		}
		tokens, err := service.RefreshToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceRefresh,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		refreshTokenString, _ := token.SignedString([]byte("test-secret-key"))

		dto := domain.RefreshTokenDTO{
			RefreshToken: refreshTokenString,
		}
		tokens, err := service.RefreshToken(context.Background(), dto)

		assert.Error(t, err)
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
	})
}

func TestAuthService_GenerateToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success with access token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-123",
			Audience: domain.TokenAudienceAccess,
		}

		token, err := service.GenerateToken(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token is valid
		verifyDTO := domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceAccess,
		}
		verifiedToken, err := service.VerifyToken(context.Background(), verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, "user-uuid-123", verifiedToken.Subject)
	})

	t.Run("success with refresh token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-456",
			Audience: domain.TokenAudienceRefresh,
		}

		token, err := service.GenerateToken(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token is valid
		verifyDTO := domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceRefresh,
		}
		verifiedToken, err := service.VerifyToken(context.Background(), verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, "user-uuid-456", verifiedToken.Subject)
	})

	t.Run("success with exchange token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-789",
			Audience: domain.TokenAudienceExchange,
		}

		token, err := service.GenerateToken(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token is valid
		verifyDTO := domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceExchange,
		}
		verifiedToken, err := service.VerifyToken(context.Background(), verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, "user-uuid-789", verifiedToken.Subject)
	})
}

func TestAuthService_AddUserOAuthProvider(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		provider := domain.UserOAuthProvider{
			UUID:           "provider-uuid-123",
			UserUUID:       "user-uuid-123",
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google-123",
			ProviderEmail:  "user@example.com",
			CreatedAt:      1234567890,
		}

		dto := domain.AddUserOAuthProviderDTO{
			UserUUID:       "user-uuid-123",
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google-123",
			ProviderEmail:  "user@example.com",
		}

		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == dto.UserUUID && p.Provider == dto.Provider
		})).Return(&provider, nil).Once()

		result, err := service.AddUserOAuthProvider(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, provider.UUID, result.UUID)
		authRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		dto := domain.AddUserOAuthProviderDTO{
			UserUUID:       "user-uuid-123",
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google-123",
			ProviderEmail:  "user@example.com",
		}

		authRepo.On("CreateUserOAuthProvider", mock.AnythingOfType("domain.UserOAuthProvider")).Return(nil, errors.New("db error")).Once()

		result, err := service.AddUserOAuthProvider(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_GetUserOAuthProvider(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		provider := domain.UserOAuthProvider{
			UUID:           "provider-uuid-123",
			UserUUID:       "user-uuid-123",
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google-123",
			ProviderEmail:  "user@example.com",
			CreatedAt:      1234567890,
		}

		dto := domain.GetUserOAuthProviderDTO{
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "google-123",
		}

		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", domain.OAuthProviderGoogle, "google-123").Return(&provider, nil).Once()

		result, err := service.GetUserOAuthProvider(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, provider.UUID, result.UUID)
		authRepo.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		dto := domain.GetUserOAuthProviderDTO{
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "nonexistent",
		}

		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", domain.OAuthProviderGoogle, "nonexistent").Return(nil, errors.New("not found")).Once()

		result, err := service.GetUserOAuthProvider(context.Background(), dto)

		assert.Error(t, err)
		assert.Nil(t, result)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_RemoveUserOAuthProvider(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		dto := domain.RemoveUserOAuthProviderDTO{
			UserUUID:     "user-uuid-123",
			ProviderUUID: "provider-uuid-123",
		}

		authRepo.On("DeleteUserOAuthProvider", "provider-uuid-123").Return(nil).Once()

		err := service.RemoveUserOAuthProvider(context.Background(), dto)

		assert.NoError(t, err)
		authRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		dto := domain.RemoveUserOAuthProviderDTO{
			UserUUID:     "user-uuid-123",
			ProviderUUID: "provider-uuid-123",
		}

		authRepo.On("DeleteUserOAuthProvider", "provider-uuid-123").Return(errors.New("db error")).Once()

		err := service.RemoveUserOAuthProvider(context.Background(), dto)

		assert.Error(t, err)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_GetUserOAuthProvidersByUserUUID(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		providers := []domain.UserOAuthProvider{
			{
				UUID:           "provider-uuid-1",
				UserUUID:       "user-uuid-123",
				Provider:       domain.OAuthProviderGoogle,
				ProviderUserID: "google-123",
				ProviderEmail:  "user@example.com",
				CreatedAt:      1234567890,
			},
		}

		authRepo.On("ListUserOAuthProvidersByUserUUID", "user-uuid-123").Return(providers, nil).Once()

		result, err := service.GetUserOAuthProvidersByUserUUID(context.Background(), "user-uuid-123")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, providers[0].UUID, result[0].UUID)
		authRepo.AssertExpectations(t)
	})

	t.Run("empty list", func(t *testing.T) {
		providers := []domain.UserOAuthProvider{}

		authRepo.On("ListUserOAuthProvidersByUserUUID", "user-uuid-456").Return(providers, nil).Once()

		result, err := service.GetUserOAuthProvidersByUserUUID(context.Background(), "user-uuid-456")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 0)
		authRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		authRepo.On("ListUserOAuthProvidersByUserUUID", "user-uuid-789").Return(nil, errors.New("db error")).Once()

		result, err := service.GetUserOAuthProvidersByUserUUID(context.Background(), "user-uuid-789")

		assert.Error(t, err)
		assert.Nil(t, result)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_GetOAuthProviderAuthURL(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		providerMock := new(mocks.OAuthProviderMock)
		providerMock.On("GetAuthURL", "test-state").Return("https://provider.com/auth?state=test-state").Once()

		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()

		url, err := service.GetOAuthProviderAuthURL(context.Background(), domain.OAuthProviderGoogle, "test-state")

		assert.NoError(t, err)
		assert.Equal(t, "https://provider.com/auth?state=test-state", url)
		oauthProviderRegistry.AssertExpectations(t)
		providerMock.AssertExpectations(t)
	})

	t.Run("provider not configured", func(t *testing.T) {
		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(nil, errors.New("provider not configured")).Once()

		url, err := service.GetOAuthProviderAuthURL(context.Background(), domain.OAuthProviderGoogle, "test-state")

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.oauthProvider.invalid", validationErr.Error())
		assert.Empty(t, url)
		oauthProviderRegistry.AssertExpectations(t)
	})
}

func TestAuthService_GetOAuthProviderUserInfo(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, "test-secret-key")

	t.Run("success", func(t *testing.T) {
		providerMock := new(mocks.OAuthProviderMock)
		userInfo := &domain.OAuthProviderUserInfo{
			ID:    "provider-user-id",
			Name:  "Test User",
			Email: "test@example.com",
		}

		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), "auth-code").Return(userInfo, nil).Once()

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "auth-code")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "provider-user-id", result.ID)
		assert.Equal(t, "Test User", result.Name)
		assert.Equal(t, "test@example.com", result.Email)
		oauthProviderRegistry.AssertExpectations(t)
		providerMock.AssertExpectations(t)
	})

	t.Run("provider not configured", func(t *testing.T) {
		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(nil, errors.New("provider not configured")).Once()

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "auth-code")

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.oauthProvider.invalid", validationErr.Error())
		assert.Nil(t, result)
		oauthProviderRegistry.AssertExpectations(t)
	})

	t.Run("user info retrieval fails", func(t *testing.T) {
		providerMock := new(mocks.OAuthProviderMock)

		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), "invalid-code").Return(nil, errors.New("invalid code")).Once()

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "invalid-code")

		require.NotNil(t, err)
		var internalErr *domain.InternalServerError
		assert.True(t, errors.As(err, &internalErr))
		assert.Equal(t, "auth.oauthProvider.userInfoFetchFailed", internalErr.Error())
		assert.Nil(t, result)
		oauthProviderRegistry.AssertExpectations(t)
		providerMock.AssertExpectations(t)
	})
}

func TestAuthService_OAuthLogin(t *testing.T) {
	const (
		provider       = domain.OAuthProviderGoogle
		providerUserID = "provider-user-id"
		code           = "auth-code"
		redirectURI    = "http://localhost:3000/callback"
		jwtSecret      = "test-secret-key"
	)

	newState := func(t *testing.T, service domain.AuthService, subject string) string {
		t.Helper()
		state, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  subject,
			Audience: domain.TokenAudienceOAuthState,
			Payload: map[string]string{
				"redirect_uri": redirectURI,
			},
		})
		require.NoError(t, err)
		return state
	}

	t.Run("success - existing linked user (Case 1)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}
		userOAuthProvider := &domain.UserOAuthProvider{UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID}
		user := &domain.User{UUID: userUUID, Email: "test@example.com", Name: "Test User"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(userOAuthProvider, nil).Once()
		usersService.On("GetByUUID", userUUID).Return(user, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, userUUID, result.User.UUID)
		assert.Equal(t, redirectURI, result.RedirectURI)
		assert.NotEmpty(t, result.Tokens.AccessToken)
		assert.NotEmpty(t, result.Tokens.RefreshToken)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
	})

	t.Run("success - link to existing user by email (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}
		user := &domain.User{UUID: userUUID, Email: email, Name: "Test User"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(user, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == userUUID && p.Provider == provider && p.ProviderUserID == providerUserID
		})).Return(&domain.UserOAuthProvider{}, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, userUUID, result.User.UUID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
	})

	t.Run("error - email not verified (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: false}
		existingUser := &domain.User{UUID: "user-uuid", Email: email}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(existingUser, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.emailNotVerified", err.Error())
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "CreateOAuth")
		authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
	})

	t.Run("success - create new user (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		newUserUUID := "new-user-uuid"
		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email}
		newUser := &domain.User{UUID: newUserUUID, Email: email, Name: name}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email}).Return(newUser, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == newUserUUID && p.Provider == provider
		})).Return(&domain.UserOAuthProvider{}, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, newUserUUID, result.User.UUID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
	})

	t.Run("error - create user fails (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email}).Return(nil, errors.New("db error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertExpectations(t)
		authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
	})

	t.Run("error - link fails after create, rollback runs (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		newUserUUID := "new-user-uuid"
		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email}
		newUser := &domain.User{UUID: newUserUUID, Email: email, Name: name}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email}).Return(newUser, nil).Once()
		linkErr := errors.New("db error")
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == newUserUUID
		})).Return(nil, linkErr).Once()
		usersService.On("Delete", newUserUUID).Return(nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Equal(t, linkErr, err)
		assert.Nil(t, result)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
	})

	t.Run("error - fetch user fails (Case 1)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}
		userOAuthProvider := &domain.UserOAuthProvider{UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(userOAuthProvider, nil).Once()
		usersService.On("GetByUUID", userUUID).Return(nil, errors.New("db error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertExpectations(t)
	})

	t.Run("error - link fails (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}
		user := &domain.User{UUID: userUUID, Email: email}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(user, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == userUUID
		})).Return(nil, errors.New("db error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "Delete", mock.Anything)
	})

	t.Run("error - invalid state token", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{
			Provider: provider,
			State:    "invalid-state",
			Code:     code,
		})

		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("error - state subject does not match callback provider", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)

		state := newState(t, service, string(domain.OAuthProviderGitHub))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{
			Provider: domain.OAuthProviderGoogle,
			State:    state,
			Code:     code,
		})

		require.NotNil(t, err)
		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
		assert.Equal(t, "auth.oauthLogin.providerMismatch", err.Error())
		assert.Nil(t, result)
	})

	t.Run("error - invalid redirect_uri in state payload", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)

		state, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{},
		})
		require.NoError(t, err)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.invalidStatePayload", err.Error())
		assert.Nil(t, result)
	})

	t.Run("error - provider userinfo fetch fails", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(nil, errors.New("provider error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("error - missing required fields from provider", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		userInfo := &domain.OAuthProviderUserInfo{ID: "", Name: "Test User", Email: "test@example.com"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.invalidUserInfo", err.Error())
		assert.Nil(t, result)
	})

	t.Run("error - GetUserOAuthProvider fails with non-NotFound error", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, errors.New("db down")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "GetByEmail", mock.Anything)
	})

	t.Run("error - GetByEmail fails with non-NotFound error", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, jwtSecret)
		providerMock := new(mocks.OAuthProviderMock)

		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, errors.New("db down")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
	})
}
