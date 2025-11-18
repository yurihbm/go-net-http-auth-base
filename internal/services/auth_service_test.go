package services_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestNewAuthService(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)
	assert.NotNil(t, service)
}

func TestAuthService_CredentialsLogin(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

	// Set JWT_SECRET for token generation
	_ = os.Setenv("JWT_SECRET", "test-secret-key")
	t.Cleanup(func() {
		_ = os.Unsetenv("JWT_SECRET")
	})

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

		tokens, err := service.CredentialsLogin(dto)

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

		usersService.On("GetByEmail", dto.Email).Return(nil, nil).Once()

		tokens, err := service.CredentialsLogin(dto)

		assert.Error(t, err)
		assert.Equal(t, "auth.authenticate.user_not_found", err.Error())
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

		tokens, err := service.CredentialsLogin(dto)

		assert.Error(t, err)
		assert.Equal(t, "auth.authenticate.user_not_found", err.Error())
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

		tokens, err := service.CredentialsLogin(dto)

		assert.Error(t, err)
		assert.Equal(t, "auth.authenticate.invalid_credentials", err.Error())
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
		usersService.AssertExpectations(t)
	})
}

func TestAuthService_VerifyToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

	// Set JWT_SECRET for token generation/verification
	_ = os.Setenv("JWT_SECRET", "test-secret-key")
	t.Cleanup(func() {
		_ = os.Unsetenv("JWT_SECRET")
	})

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
		result, err := service.VerifyToken(dto)

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
		result, err := service.VerifyToken(dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid token format", func(t *testing.T) {
		dto := domain.VerifyTokenDTO{
			Token:    "invalid-token",
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(dto)

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
		result, err := service.VerifyToken(dto)

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
		result, err := service.VerifyToken(dto)

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
		result, err := service.VerifyToken(dto)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

	// Set JWT_SECRET for token generation/verification
	_ = os.Setenv("JWT_SECRET", "test-secret-key")
	t.Cleanup(func() {
		_ = os.Unsetenv("JWT_SECRET")
	})

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
		tokens, err := service.RefreshToken(dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)

		// Verify the new access token contains the correct user UUID
		verifyDTO := domain.VerifyTokenDTO{
			Token:    tokens.AccessToken,
			Audience: domain.TokenAudienceAccess,
		}
		verifiedToken, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, userUUID, verifiedToken.Subject)

		// Verify the new refresh token contains the correct user UUID
		verifyDTO = domain.VerifyTokenDTO{
			Token:    tokens.RefreshToken,
			Audience: domain.TokenAudienceRefresh,
		}
		verifiedToken, err = service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, userUUID, verifiedToken.Subject)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		dto := domain.RefreshTokenDTO{
			RefreshToken: "invalid-token",
		}
		tokens, err := service.RefreshToken(dto)

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
		tokens, err := service.RefreshToken(dto)

		assert.Error(t, err)
		assert.Empty(t, tokens.AccessToken)
		assert.Empty(t, tokens.RefreshToken)
	})
}

func TestAuthService_GenerateToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

	// Set JWT_SECRET for token generation
	_ = os.Setenv("JWT_SECRET", "test-secret-key")
	t.Cleanup(func() {
		_ = os.Unsetenv("JWT_SECRET")
	})

	t.Run("success with access token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-123",
			Audience: domain.TokenAudienceAccess,
		}

		token, err := service.GenerateToken(dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token is valid
		verifyDTO := domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceAccess,
		}
		verifiedToken, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, "user-uuid-123", verifiedToken.Subject)
	})

	t.Run("success with refresh token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-456",
			Audience: domain.TokenAudienceRefresh,
		}

		token, err := service.GenerateToken(dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token is valid
		verifyDTO := domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceRefresh,
		}
		verifiedToken, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, "user-uuid-456", verifiedToken.Subject)
	})

	t.Run("success with exchange token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-789",
			Audience: domain.TokenAudienceExchange,
		}

		token, err := service.GenerateToken(dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token is valid
		verifyDTO := domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceExchange,
		}
		verifiedToken, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)
		assert.Equal(t, "user-uuid-789", verifiedToken.Subject)
	})
}

func TestAuthService_AddUserOAuthProvider(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

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

		result, err := service.AddUserOAuthProvider(dto)

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

		result, err := service.AddUserOAuthProvider(dto)

		assert.Error(t, err)
		assert.Nil(t, result)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_GetUserOAuthProvider(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

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

		result, err := service.GetUserOAuthProvider(dto)

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

		result, err := service.GetUserOAuthProvider(dto)

		assert.Error(t, err)
		assert.Nil(t, result)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_RemoveUserOAuthProvider(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

	t.Run("success", func(t *testing.T) {
		dto := domain.RemoveUserOAuthProviderDTO{
			UserUUID:     "user-uuid-123",
			ProviderUUID: "provider-uuid-123",
		}

		authRepo.On("DeleteUserOAuthProvider", "provider-uuid-123").Return(nil).Once()

		err := service.RemoveUserOAuthProvider(dto)

		assert.NoError(t, err)
		authRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		dto := domain.RemoveUserOAuthProviderDTO{
			UserUUID:     "user-uuid-123",
			ProviderUUID: "provider-uuid-123",
		}

		authRepo.On("DeleteUserOAuthProvider", "provider-uuid-123").Return(errors.New("db error")).Once()

		err := service.RemoveUserOAuthProvider(dto)

		assert.Error(t, err)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_GetUserOAuthProvidersByUserUUID(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

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

		result, err := service.GetUserOAuthProvidersByUserUUID("user-uuid-123")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, providers[0].UUID, result[0].UUID)
		authRepo.AssertExpectations(t)
	})

	t.Run("empty list", func(t *testing.T) {
		providers := []domain.UserOAuthProvider{}

		authRepo.On("ListUserOAuthProvidersByUserUUID", "user-uuid-456").Return(providers, nil).Once()

		result, err := service.GetUserOAuthProvidersByUserUUID("user-uuid-456")

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 0)
		authRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		authRepo.On("ListUserOAuthProvidersByUserUUID", "user-uuid-789").Return(nil, errors.New("db error")).Once()

		result, err := service.GetUserOAuthProvidersByUserUUID("user-uuid-789")

		assert.Error(t, err)
		assert.Nil(t, result)
		authRepo.AssertExpectations(t)
	})
}

func TestAuthService_GetOAuthProviderAuthURL(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

	t.Run("success", func(t *testing.T) {
		providerMock := new(mocks.OAuthProviderMock)
		providerMock.On("GetAuthURL", "test-state").Return("https://provider.com/auth?state=test-state").Once()

		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()

		url, err := service.GetOAuthProviderAuthURL(domain.OAuthProviderGoogle, "test-state")

		assert.NoError(t, err)
		assert.Equal(t, "https://provider.com/auth?state=test-state", url)
		oauthProviderRegistry.AssertExpectations(t)
		providerMock.AssertExpectations(t)
	})

	t.Run("provider not configured", func(t *testing.T) {
		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(nil, errors.New("provider not configured")).Once()

		url, err := service.GetOAuthProviderAuthURL(domain.OAuthProviderGoogle, "test-state")

		assert.Error(t, err)
		assert.Empty(t, url)
		assert.Equal(t, "provider not configured", err.Error())
		oauthProviderRegistry.AssertExpectations(t)
	})
}

func TestAuthService_GetOAuthProviderUserInfo(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry)

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

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "provider not configured", err.Error())
		oauthProviderRegistry.AssertExpectations(t)
	})

	t.Run("user info retrieval fails", func(t *testing.T) {
		providerMock := new(mocks.OAuthProviderMock)

		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), "invalid-code").Return(nil, errors.New("invalid code")).Once()

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "invalid-code")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "invalid code", err.Error())
		oauthProviderRegistry.AssertExpectations(t)
		providerMock.AssertExpectations(t)
	})
}
