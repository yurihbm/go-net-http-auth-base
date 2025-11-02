package services_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestNewAuthService(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	service := services.NewAuthService(usersService)
	assert.NotNil(t, service)
}

func TestAuthService_CredentialsLogin(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	service := services.NewAuthService(usersService)

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
	service := services.NewAuthService(usersService)

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
		assert.Equal(t, userUUID, result)
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
		assert.Empty(t, result)
	})

	t.Run("invalid token format", func(t *testing.T) {
		dto := domain.VerifyTokenDTO{
			Token:    "invalid-token",
			Audience: domain.TokenAudienceAccess,
		}
		result, err := service.VerifyToken(dto)

		assert.Error(t, err)
		assert.Empty(t, result)
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
		assert.Empty(t, result)
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
		assert.Empty(t, result)
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
		assert.Empty(t, result)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	service := services.NewAuthService(usersService)

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
		verifiedUUID, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.Equal(t, userUUID, verifiedUUID)

		// Verify the new refresh token contains the correct user UUID
		verifyDTO = domain.VerifyTokenDTO{
			Token:    tokens.RefreshToken,
			Audience: domain.TokenAudienceRefresh,
		}
		verifiedUUID, err = service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.Equal(t, userUUID, verifiedUUID)
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
	service := services.NewAuthService(usersService)

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
		verifiedUUID, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.Equal(t, "user-uuid-123", verifiedUUID)
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
		verifiedUUID, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.Equal(t, "user-uuid-456", verifiedUUID)
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
		verifiedUUID, err := service.VerifyToken(verifyDTO)
		assert.NoError(t, err)
		assert.Equal(t, "user-uuid-789", verifiedUUID)
	})
}
