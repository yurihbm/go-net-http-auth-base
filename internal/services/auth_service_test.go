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

const testSessionMaxAge = 30 * 24 * time.Hour

func newTransactorMock() *mocks.TransactorMock {
	transactor := new(mocks.TransactorMock)
	transactor.On("WithinTx").Return()
	return transactor
}

func TestNewAuthService(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)
	assert.NotNil(t, service)
}

func TestAuthService_CredentialsLogin(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

	t.Run("success", func(t *testing.T) {
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			UUID:         "user-uuid-123",
			Name:         "Test User",
			Email:        "test@example.com",
			PasswordHash: string(hashedPassword),
			Role:         domain.RoleAdmin,
		}

		dto := domain.CredentialsLoginDTO{
			Email:    "test@example.com",
			Password: password,
		}

		usersService.On("GetByEmail", dto.Email).Return(user, nil).Once()
		var storedJTI *string
		usersService.On("SetRefreshJTI", user.UUID, mock.AnythingOfType("*string")).Return(nil).Once().Run(func(args mock.Arguments) {
			storedJTI = args.Get(1).(*string)
		})

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		verified, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
			Token:    tokens.AccessToken,
			Audience: domain.TokenAudienceAccess,
		})
		assert.NoError(t, err)
		assert.Equal(t, domain.RoleAdmin, verified.Role)
		refresh, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
			Token:    tokens.RefreshToken,
			Audience: domain.TokenAudienceRefresh,
		})
		require.NoError(t, err)
		require.NotNil(t, storedJTI)
		assert.NotEmpty(t, *storedJTI)
		assert.Equal(t, *storedJTI, refresh.ID)
		assert.InDelta(t, time.Now().Unix(), refresh.AuthTime, 5)
		usersService.AssertExpectations(t)
	})

	t.Run("each login replaces the stored refresh jti", func(t *testing.T) {
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		user := &domain.User{UUID: "user-uuid-single-session", Email: "single@example.com", PasswordHash: string(hashedPassword)}
		dto := domain.CredentialsLoginDTO{Email: user.Email, Password: password}
		usersService.On("GetByEmail", dto.Email).Return(user, nil).Twice()
		var storedJTIs []string
		usersService.On("SetRefreshJTI", user.UUID, mock.AnythingOfType("*string")).Return(nil).Twice().Run(func(args mock.Arguments) {
			storedJTIs = append(storedJTIs, *args.Get(1).(*string))
		})

		_, err := service.CredentialsLogin(context.Background(), dto)
		require.NoError(t, err)
		_, err = service.CredentialsLogin(context.Background(), dto)
		require.NoError(t, err)

		require.Len(t, storedJTIs, 2)
		assert.NotEqual(t, storedJTIs[0], storedJTIs[1])
	})

	t.Run("session store failure", func(t *testing.T) {
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		user := &domain.User{UUID: "user-uuid-store-failure", Email: "store@example.com", PasswordHash: string(hashedPassword)}
		dto := domain.CredentialsLoginDTO{Email: user.Email, Password: password}
		usersService.On("GetByEmail", dto.Email).Return(user, nil).Once()
		usersService.On("SetRefreshJTI", user.UUID, mock.AnythingOfType("*string")).Return(errors.New("db down")).Once()

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		var internalErr *domain.InternalServerError
		assert.ErrorAs(t, err, &internalErr)
		assert.Empty(t, tokens)
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
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

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

func signTestToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret-key"))
	require.NoError(t, err)
	return signed
}

func refreshClaims(userUUID string, jti any, authTime any) jwt.MapClaims {
	claims := jwt.MapClaims{
		"sub": userUUID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"aud": domain.TokenAudienceRefresh,
	}
	if jti != nil {
		claims["jti"] = jti
	}
	if authTime != nil {
		claims["auth_time"] = authTime
	}
	return claims
}

func TestAuthService_RefreshToken(t *testing.T) {
	const (
		userUUID   = "user-uuid-123"
		currentJTI = "current-jti"
	)
	authTime := time.Now().Add(-time.Hour).Unix()

	newService := func() (domain.AuthService, *mocks.UsersServiceMock) {
		usersService := new(mocks.UsersServiceMock)
		service := services.NewAuthService(usersService, new(mocks.AuthRepositoryMock), new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)
		return service, usersService
	}

	t.Run("success rotates the jti and keeps auth_time", func(t *testing.T) {
		service, usersService := newService()
		refreshToken := signTestToken(t, refreshClaims(userUUID, currentJTI, authTime))
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID, Role: domain.RoleAdmin}, nil).Once()
		var nextJTI string
		usersService.On("RotateRefreshJTI", userUUID, currentJTI, mock.AnythingOfType("string")).Return(nil).Once().Run(func(args mock.Arguments) {
			nextJTI = args.String(2)
		})

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})

		require.NoError(t, err)
		usersService.AssertExpectations(t)
		access, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{Token: tokens.AccessToken, Audience: domain.TokenAudienceAccess})
		require.NoError(t, err)
		assert.Equal(t, userUUID, access.Subject)
		assert.Equal(t, domain.RoleAdmin, access.Role)
		refresh, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{Token: tokens.RefreshToken, Audience: domain.TokenAudienceRefresh})
		require.NoError(t, err)
		assert.Equal(t, userUUID, refresh.Subject)
		assert.NotEmpty(t, nextJTI)
		assert.NotEqual(t, currentJTI, nextJTI)
		assert.Equal(t, nextJTI, refresh.ID)
		assert.Equal(t, authTime, refresh.AuthTime)
	})

	t.Run("stale jti is rejected", func(t *testing.T) {
		service, usersService := newService()
		refreshToken := signTestToken(t, refreshClaims(userUUID, "stale-jti", authTime))
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID}, nil).Once()
		usersService.On("RotateRefreshJTI", userUUID, "stale-jti", mock.AnythingOfType("string")).Return(domain.NewNotFoundError("users.refreshSession.notFound")).Once()

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
	})

	t.Run("deleted user is rejected", func(t *testing.T) {
		service, usersService := newService()
		refreshToken := signTestToken(t, refreshClaims(userUUID, currentJTI, authTime))
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(nil, domain.NewNotFoundError("users.notFound")).Once()

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
		usersService.AssertNotCalled(t, "RotateRefreshJTI", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("user lookup internal error is returned", func(t *testing.T) {
		service, usersService := newService()
		refreshToken := signTestToken(t, refreshClaims(userUUID, currentJTI, authTime))
		lookupErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(nil, lookupErr).Once()

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})

		assert.ErrorIs(t, err, lookupErr)
		assert.Empty(t, tokens)
	})

	t.Run("rotation internal error is returned", func(t *testing.T) {
		service, usersService := newService()
		refreshToken := signTestToken(t, refreshClaims(userUUID, currentJTI, authTime))
		rotateErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID}, nil).Once()
		usersService.On("RotateRefreshJTI", userUUID, currentJTI, mock.AnythingOfType("string")).Return(rotateErr).Once()

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})

		assert.ErrorIs(t, err, rotateErr)
		assert.Empty(t, tokens)
	})

	t.Run("session older than the max age is rejected", func(t *testing.T) {
		service, usersService := newService()
		expiredAuthTime := time.Now().Add(-testSessionMaxAge - time.Minute).Unix()
		refreshToken := signTestToken(t, refreshClaims(userUUID, currentJTI, expiredAuthTime))

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
		usersService.AssertNotCalled(t, "GetByUUID", mock.Anything, mock.Anything)
	})

	claimCases := []struct {
		name     string
		jti      any
		authTime any
	}{
		{"missing jti", nil, authTime},
		{"missing auth_time", currentJTI, nil},
		{"empty jti", "", authTime},
		{"non-string jti", 123, authTime},
		{"non-numeric auth_time", currentJTI, "yesterday"},
	}
	for _, tc := range claimCases {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			service, usersService := newService()
			refreshToken := signTestToken(t, refreshClaims(userUUID, tc.jti, tc.authTime))

			var tokens domain.AuthTokens
			var err error
			assert.NotPanics(t, func() {
				tokens, err = service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: refreshToken})
			})

			assert.ErrorIs(t, err, services.ErrInvalidToken)
			assert.Empty(t, tokens)
			usersService.AssertNotCalled(t, "GetByUUID", mock.Anything, mock.Anything)
		})
	}

	t.Run("invalid refresh token", func(t *testing.T) {
		service, _ := newService()

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: "invalid-token"})

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		service, _ := newService()
		claims := refreshClaims(userUUID, currentJTI, authTime)
		claims["exp"] = time.Now().Add(-time.Hour).Unix()

		tokens, err := service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: signTestToken(t, claims)})

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})
}

func TestAuthService_Logout(t *testing.T) {
	const userUUID = "user-uuid-123"

	newService := func() (domain.AuthService, *mocks.UsersServiceMock) {
		usersService := new(mocks.UsersServiceMock)
		service := services.NewAuthService(usersService, new(mocks.AuthRepositoryMock), new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)
		return service, usersService
	}
	accessToken := func(t *testing.T) string {
		return signTestToken(t, jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Minute).Unix(),
			"aud": domain.TokenAudienceAccess,
		})
	}

	t.Run("clears the stored refresh jti", func(t *testing.T) {
		service, usersService := newService()
		usersService.On("SetRefreshJTI", userUUID, (*string)(nil)).Return(nil).Once()

		err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: accessToken(t)})

		assert.NoError(t, err)
		usersService.AssertExpectations(t)
	})

	for name, token := range map[string]string{"missing": "", "invalid": "not-a-jwt"} {
		t.Run("tolerates "+name+" access token", func(t *testing.T) {
			service, usersService := newService()

			err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: token})

			assert.NoError(t, err)
			usersService.AssertNotCalled(t, "SetRefreshJTI", mock.Anything, mock.Anything)
		})
	}

	t.Run("clears the stored refresh jti with an expired access token", func(t *testing.T) {
		service, usersService := newService()
		expired := signTestToken(t, jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour).Unix(),
			"aud": domain.TokenAudienceAccess,
		})
		usersService.On("SetRefreshJTI", userUUID, (*string)(nil)).Return(nil).Once()

		err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: expired})

		assert.NoError(t, err)
		usersService.AssertExpectations(t)
	})

	t.Run("ignores an expired access token with a bad signature", func(t *testing.T) {
		service, usersService := newService()
		forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour).Unix(),
			"aud": domain.TokenAudienceAccess,
		}).SignedString([]byte("other-secret"))
		require.NoError(t, err)

		err = service.Logout(context.Background(), domain.LogoutDTO{AccessToken: forged})

		assert.NoError(t, err)
		usersService.AssertNotCalled(t, "SetRefreshJTI", mock.Anything, mock.Anything)
	})

	t.Run("ignores an expired token with the wrong audience", func(t *testing.T) {
		service, usersService := newService()
		expired := signTestToken(t, jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(-time.Hour).Unix(),
			"aud": domain.TokenAudienceEmailVerification,
		})

		err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: expired})

		assert.NoError(t, err)
		usersService.AssertNotCalled(t, "SetRefreshJTI", mock.Anything, mock.Anything)
	})

	t.Run("ignores an expired access token without subject", func(t *testing.T) {
		service, usersService := newService()
		expired := signTestToken(t, jwt.MapClaims{
			"exp": time.Now().Add(-time.Hour).Unix(),
			"aud": domain.TokenAudienceAccess,
		})

		err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: expired})

		assert.NoError(t, err)
		usersService.AssertNotCalled(t, "SetRefreshJTI", mock.Anything, mock.Anything)
	})

	t.Run("ignores a refresh token presented as access token", func(t *testing.T) {
		service, usersService := newService()
		refreshToken := signTestToken(t, refreshClaims(userUUID, "jti", time.Now().Unix()))

		err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: refreshToken})

		assert.NoError(t, err)
		usersService.AssertNotCalled(t, "SetRefreshJTI", mock.Anything, mock.Anything)
	})

	t.Run("returns the clear error", func(t *testing.T) {
		service, usersService := newService()
		clearErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		usersService.On("SetRefreshJTI", userUUID, (*string)(nil)).Return(clearErr).Once()

		err := service.Logout(context.Background(), domain.LogoutDTO{AccessToken: accessToken(t)})

		assert.ErrorIs(t, err, clearErr)
	})
}

func TestAuthService_GenerateToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

	t.Run("success with access token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-123",
			Audience: domain.TokenAudienceAccess,
		}

		token, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), dto)

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

	t.Run("role is carried in the token", func(t *testing.T) {
		token, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  "user-uuid-123",
			Audience: domain.TokenAudienceAccess,
			Role:     domain.RoleAdmin,
		})
		assert.NoError(t, err)

		verifiedToken, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
			Token:    token,
			Audience: domain.TokenAudienceAccess,
		})
		assert.NoError(t, err)
		assert.Equal(t, domain.RoleAdmin, verifiedToken.Role)
	})

	t.Run("success with refresh token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:  "user-uuid-456",
			Audience: domain.TokenAudienceRefresh,
		}

		token, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), dto)

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

		token, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), dto)

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
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

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
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

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
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

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
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

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

func TestAuthService_StartOAuthLogin(t *testing.T) {
	const redirectURI = "http://localhost:3000/callback"

	newService := func() (domain.AuthService, *mocks.OAuthProviderRegistryMock) {
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(new(mocks.UsersServiceMock), new(mocks.AuthRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)
		return service, oauthProviderRegistry
	}

	t.Run("success", func(t *testing.T) {
		service, oauthProviderRegistry := newService()
		providerMock := new(mocks.OAuthProviderMock)
		var state, verifier string
		providerMock.On("GetAuthURL", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			state = args.String(0)
			verifier = args.String(1)
		}).Return("https://provider.com/auth").Once()
		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()

		result, err := service.StartOAuthLogin(context.Background(), domain.StartOAuthLoginDTO{
			Provider:    domain.OAuthProviderGoogle,
			RedirectURI: redirectURI,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "https://provider.com/auth", result.AuthURL)
		assert.NotEmpty(t, result.Nonce)
		assert.GreaterOrEqual(t, len(result.CodeVerifier), 43)
		assert.Equal(t, verifier, result.CodeVerifier)
		assert.NotEqual(t, result.Nonce, result.CodeVerifier)

		tokenData, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		})
		require.NoError(t, err)
		assert.Equal(t, string(domain.OAuthProviderGoogle), tokenData.Subject)
		payload, ok := tokenData.Payload.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, redirectURI, payload["redirect_uri"])
		assert.Equal(t, result.Nonce, payload["nonce"])
		providerMock.AssertExpectations(t)
		oauthProviderRegistry.AssertExpectations(t)
	})

	t.Run("nonce and verifier are unique per call", func(t *testing.T) {
		service, oauthProviderRegistry := newService()
		providerMock := new(mocks.OAuthProviderMock)
		providerMock.On("GetAuthURL", mock.Anything, mock.Anything).Return("https://provider.com/auth")
		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil)
		dto := domain.StartOAuthLoginDTO{Provider: domain.OAuthProviderGoogle, RedirectURI: redirectURI}

		first, err := service.StartOAuthLogin(context.Background(), dto)
		require.NoError(t, err)
		second, err := service.StartOAuthLogin(context.Background(), dto)
		require.NoError(t, err)

		assert.NotEqual(t, first.Nonce, second.Nonce)
		assert.NotEqual(t, first.CodeVerifier, second.CodeVerifier)
	})

	t.Run("provider not configured", func(t *testing.T) {
		service, oauthProviderRegistry := newService()
		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(nil, errors.New("provider not configured")).Once()

		result, err := service.StartOAuthLogin(context.Background(), domain.StartOAuthLoginDTO{
			Provider:    domain.OAuthProviderGoogle,
			RedirectURI: redirectURI,
		})

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.oauthProvider.invalid", validationErr.Error())
		assert.Nil(t, result)
		oauthProviderRegistry.AssertExpectations(t)
	})
}

func TestAuthService_GetOAuthProviderUserInfo(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)

	t.Run("success", func(t *testing.T) {
		providerMock := new(mocks.OAuthProviderMock)
		userInfo := &domain.OAuthProviderUserInfo{
			ID:    "provider-user-id",
			Name:  "Test User",
			Email: "test@example.com",
		}

		oauthProviderRegistry.On("Get", domain.OAuthProviderGoogle).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), "auth-code", "verifier").Return(userInfo, nil).Once()

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "auth-code", "verifier")

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

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "auth-code", "verifier")

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
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), "invalid-code", "verifier").Return(nil, errors.New("invalid code")).Once()

		result, err := service.GetOAuthProviderUserInfo(context.Background(), domain.OAuthProviderGoogle, "invalid-code", "verifier")

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
		nonce          = "browser-nonce"
		codeVerifier   = "code-verifier"
	)

	newState := func(t *testing.T, service domain.AuthService, subject string) string {
		t.Helper()
		state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  subject,
			Audience: domain.TokenAudienceOAuthState,
			Payload: map[string]string{
				"redirect_uri": redirectURI,
				"nonce":        nonce,
			},
		})
		require.NoError(t, err)
		return state
	}

	t.Run("success - existing linked user (Case 1)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}
		userOAuthProvider := &domain.UserOAuthProvider{UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID}
		user := &domain.User{UUID: userUUID, Email: "test@example.com", Name: "Test User"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(userOAuthProvider, nil).Once()
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(user, nil).Once()
		var storedJTI *string
		usersService.On("SetRefreshJTI", userUUID, mock.AnythingOfType("*string")).Return(nil).Once().Run(func(args mock.Arguments) {
			storedJTI = args.Get(1).(*string)
		})

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, userUUID, result.User.UUID)
		assert.Equal(t, redirectURI, result.RedirectURI)
		assert.NotEmpty(t, result.Tokens.AccessToken)
		assert.NotEmpty(t, result.Tokens.RefreshToken)
		refresh, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{Token: result.Tokens.RefreshToken, Audience: domain.TokenAudienceRefresh})
		require.NoError(t, err)
		require.NotNil(t, storedJTI)
		assert.Equal(t, *storedJTI, refresh.ID)
		assert.InDelta(t, time.Now().Unix(), refresh.AuthTime, 5)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})

	t.Run("success - link to existing user by email (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}
		user := &domain.User{UUID: userUUID, Email: email, Name: "Test User", EmailVerified: true}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(user, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == userUUID && p.Provider == provider && p.ProviderUserID == providerUserID
		})).Return(&domain.UserOAuthProvider{}, nil).Once()
		usersService.On("SetRefreshJTI", userUUID, mock.AnythingOfType("*string")).Return(nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

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
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: false}
		existingUser := &domain.User{UUID: "user-uuid", Email: email}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(existingUser, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

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
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		newUserUUID := "new-user-uuid"
		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email, EmailVerified: true}
		newUser := &domain.User{UUID: newUserUUID, Email: email, Name: name}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email, EmailVerified: true}).Return(newUser, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == newUserUUID && p.Provider == provider
		})).Return(&domain.UserOAuthProvider{}, nil).Once()
		usersService.On("SetRefreshJTI", newUserUUID, mock.AnythingOfType("*string")).Return(nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, newUserUUID, result.User.UUID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})

	t.Run("error - create user fails (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email, EmailVerified: true}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email, EmailVerified: true}).Return(nil, errors.New("db error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertExpectations(t)
		authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
		transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})

	t.Run("error - link fails after create, error returned (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		newUserUUID := "new-user-uuid"
		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email, EmailVerified: true}
		newUser := &domain.User{UUID: newUserUUID, Email: email, Name: name}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email, EmailVerified: true}).Return(newUser, nil).Once()
		linkErr := errors.New("db error")
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == newUserUUID
		})).Return(nil, linkErr).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Equal(t, linkErr, err)
		assert.Nil(t, result)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})

	t.Run("error - fetch user fails (Case 1)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}
		userOAuthProvider := &domain.UserOAuthProvider{UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(userOAuthProvider, nil).Once()
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(nil, errors.New("db error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertExpectations(t)
	})

	t.Run("error - link fails (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}
		user := &domain.User{UUID: userUUID, Email: email, EmailVerified: true}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(user, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == userUUID
		})).Return(nil, errors.New("db error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("error - invalid state token", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{
			Provider:     provider,
			State:        "invalid-state",
			Code:         code,
			Nonce:        nonce,
			CodeVerifier: codeVerifier,
		})

		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("error - browser binding", func(t *testing.T) {
		cases := []struct {
			name         string
			nonce        string
			codeVerifier string
			stateNonce   string
			wantErr      string
		}{
			{"missing nonce cookie", "", codeVerifier, nonce, "auth.oauthLogin.nonceMismatch"},
			{"nonce differs from state", "other-nonce", codeVerifier, nonce, "auth.oauthLogin.nonceMismatch"},
			{"both nonces empty", "", codeVerifier, "", "auth.oauthLogin.nonceMismatch"},
			{"missing code verifier cookie", nonce, "", nonce, "auth.oauthLogin.missingCodeVerifier"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				usersService := new(mocks.UsersServiceMock)
				authRepo := new(mocks.AuthRepositoryMock)
				oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
				service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)

				payload := map[string]string{"redirect_uri": redirectURI}
				if tc.stateNonce != "" {
					payload["nonce"] = tc.stateNonce
				}
				state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
					Subject:  string(provider),
					Audience: domain.TokenAudienceOAuthState,
					Payload:  payload,
				})
				require.NoError(t, err)

				result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{
					Provider:     provider,
					State:        state,
					Code:         code,
					Nonce:        tc.nonce,
					CodeVerifier: tc.codeVerifier,
				})

				var unauthorizedErr *domain.UnauthorizedError
				require.True(t, errors.As(err, &unauthorizedErr))
				assert.Equal(t, tc.wantErr, err.Error())
				assert.Nil(t, result)
				oauthProviderRegistry.AssertNotCalled(t, "Get", mock.Anything)
			})
		}
	})

	t.Run("error - state subject does not match callback provider", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)

		state := newState(t, service, string(domain.OAuthProviderGitHub))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{
			Provider:     domain.OAuthProviderGoogle,
			State:        state,
			Code:         code,
			Nonce:        nonce,
			CodeVerifier: codeVerifier,
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
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)

		state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{},
		})
		require.NoError(t, err)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NotNil(t, err)
		var validationErr *domain.ValidationError
		assert.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "auth.providerCallback.invalidStatePayload", err.Error())
		assert.Nil(t, result)
	})

	t.Run("error - non-object state payload", func(t *testing.T) {
		for name, payload := range map[string]any{"nil": nil, "string": "not-an-object"} {
			t.Run(name, func(t *testing.T) {
				usersService := new(mocks.UsersServiceMock)
				authRepo := new(mocks.AuthRepositoryMock)
				oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
				service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)

				state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
					Subject:  string(provider),
					Audience: domain.TokenAudienceOAuthState,
					Payload:  payload,
				})
				require.NoError(t, err)

				result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

				var validationErr *domain.ValidationError
				require.True(t, errors.As(err, &validationErr))
				assert.Equal(t, "auth.providerCallback.invalidStatePayload", err.Error())
				assert.Nil(t, result)
			})
		}
	})

	t.Run("error - provider userinfo fetch fails", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(nil, errors.New("provider error")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("error - missing required fields from provider", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		userInfo := &domain.OAuthProviderUserInfo{ID: "", Name: "Test User", Email: "test@example.com"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

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
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, errors.New("db down")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "GetByEmail", mock.Anything)
	})

	t.Run("error - GetByEmail fails with non-NotFound error", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge)
		providerMock := new(mocks.OAuthProviderMock)

		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, errors.New("db down")).Once()

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.Error(t, err)
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
	})
}

func TestAuthService_VerifyOAuthState(t *testing.T) {
	const (
		provider    = domain.OAuthProviderGoogle
		redirectURI = "http://localhost:3000/callback"
		nonce       = "browser-nonce"
	)

	newService := func() domain.AuthService {
		return services.NewAuthService(new(mocks.UsersServiceMock), new(mocks.AuthRepositoryMock), new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge)
	}

	newState := func(t *testing.T, service domain.AuthService, subject string, payload map[string]string) string {
		t.Helper()
		state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  subject,
			Audience: domain.TokenAudienceOAuthState,
			Payload:  payload,
		})
		require.NoError(t, err)
		return state
	}

	t.Run("success returns redirect uri", func(t *testing.T) {
		service := newService()
		state := newState(t, service, string(provider), map[string]string{"redirect_uri": redirectURI, "nonce": nonce})

		got, err := service.VerifyOAuthState(context.Background(), domain.VerifyOAuthStateDTO{Provider: provider, State: state, Nonce: nonce})

		require.NoError(t, err)
		assert.Equal(t, redirectURI, got)
	})

	t.Run("error - invalid state token", func(t *testing.T) {
		got, err := newService().VerifyOAuthState(context.Background(), domain.VerifyOAuthStateDTO{Provider: provider, State: "invalid", Nonce: nonce})

		require.Error(t, err)
		assert.Empty(t, got)
	})

	t.Run("error - provider mismatch", func(t *testing.T) {
		service := newService()
		state := newState(t, service, "github", map[string]string{"redirect_uri": redirectURI, "nonce": nonce})

		got, err := service.VerifyOAuthState(context.Background(), domain.VerifyOAuthStateDTO{Provider: provider, State: state, Nonce: nonce})

		require.Error(t, err)
		assert.Equal(t, "auth.oauthLogin.providerMismatch", err.Error())
		assert.Empty(t, got)
	})

	t.Run("error - nonce mismatch or missing", func(t *testing.T) {
		for _, cookieNonce := range []string{"", "other-nonce"} {
			service := newService()
			state := newState(t, service, string(provider), map[string]string{"redirect_uri": redirectURI, "nonce": nonce})

			got, err := service.VerifyOAuthState(context.Background(), domain.VerifyOAuthStateDTO{Provider: provider, State: state, Nonce: cookieNonce})

			require.Error(t, err)
			assert.Equal(t, "auth.oauthLogin.nonceMismatch", err.Error())
			assert.Empty(t, got)
		}
	})

	t.Run("error - missing redirect uri in payload", func(t *testing.T) {
		service := newService()
		state := newState(t, service, string(provider), map[string]string{"nonce": nonce})

		got, err := service.VerifyOAuthState(context.Background(), domain.VerifyOAuthStateDTO{Provider: provider, State: state, Nonce: nonce})

		require.Error(t, err)
		assert.Empty(t, got)
	})
}
