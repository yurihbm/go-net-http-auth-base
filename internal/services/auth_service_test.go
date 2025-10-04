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
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewAuthService(repo)
	assert.NotNil(t, service)
}

func TestAuthService_Authenticate(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewAuthService(repo)

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

		dto := domain.AuthDTO{
			Email:    "test@example.com",
			Password: password,
		}

		repo.On("FindByEmail", dto.Email).Return(user, nil).Once()

		accessToken, refreshToken, err := service.Authenticate(dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
		repo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		dto := domain.AuthDTO{
			Email:    "notfound@example.com",
			Password: "password123",
		}

		repo.On("FindByEmail", dto.Email).Return(nil, nil).Once()

		accessToken, refreshToken, err := service.Authenticate(dto)

		assert.Error(t, err)
		assert.Equal(t, "auth.authenticate.user_not_found", err.Error())
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
		repo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		dto := domain.AuthDTO{
			Email:    "test@example.com",
			Password: "password123",
		}

		repo.On("FindByEmail", dto.Email).Return(nil, errors.New("db error")).Once()

		accessToken, refreshToken, err := service.Authenticate(dto)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
		repo.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
		user := &domain.User{
			UUID:         "user-uuid-123",
			Name:         "Test User",
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
		}

		dto := domain.AuthDTO{
			Email:    "test@example.com",
			Password: "wrong-password",
		}

		repo.On("FindByEmail", dto.Email).Return(user, nil).Once()

		accessToken, refreshToken, err := service.Authenticate(dto)

		assert.Error(t, err)
		assert.Equal(t, "auth.authenticate.invalid_credentials", err.Error())
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
		repo.AssertExpectations(t)
	})
}

func TestAuthService_VerifyToken(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewAuthService(repo)

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
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("test-secret-key"))

		result, err := service.VerifyToken(tokenString)

		assert.NoError(t, err)
		assert.Equal(t, userUUID, result)
	})

	t.Run("expired token", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour * 1).Unix(), // expired 1 hour ago
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("test-secret-key"))

		result, err := service.VerifyToken(tokenString)

		assert.Error(t, err)
		assert.Empty(t, result)
	})

	t.Run("invalid token format", func(t *testing.T) {
		result, err := service.VerifyToken("invalid-token")

		assert.Error(t, err)
		assert.Empty(t, result)
	})

	t.Run("token with wrong signing method", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		}
		// Sign with RSA instead of HMAC
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

		result, err := service.VerifyToken(tokenString)

		assert.Error(t, err)
		assert.Empty(t, result)
	})

	t.Run("token signed with different secret", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("different-secret-key"))

		result, err := service.VerifyToken(tokenString)

		assert.Error(t, err)
		assert.Empty(t, result)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewAuthService(repo)

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
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		refreshTokenString, _ := token.SignedString([]byte("test-secret-key"))

		accessToken, newRefreshToken, err := service.RefreshToken(refreshTokenString)

		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, newRefreshToken)

		// Verify the new access token contains the correct user UUID
		verifiedUUID, err := service.VerifyToken(accessToken)
		assert.NoError(t, err)
		assert.Equal(t, userUUID, verifiedUUID)

		// Verify the new refresh token contains the correct user UUID
		verifiedUUID, err = service.VerifyToken(newRefreshToken)
		assert.NoError(t, err)
		assert.Equal(t, userUUID, verifiedUUID)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		accessToken, refreshToken, err := service.RefreshToken("invalid-token")

		assert.Error(t, err)
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour * 1).Unix(), // expired
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		refreshTokenString, _ := token.SignedString([]byte("test-secret-key"))

		accessToken, newRefreshToken, err := service.RefreshToken(refreshTokenString)

		assert.Error(t, err)
		assert.Empty(t, accessToken)
		assert.Empty(t, newRefreshToken)
	})
}
