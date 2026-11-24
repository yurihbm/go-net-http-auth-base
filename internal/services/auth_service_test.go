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

const (
	testSessionMaxAge = 30 * 24 * time.Hour
	testMaxSessions   = 10
)

func newTransactorMock() *mocks.TransactorMock {
	transactor := new(mocks.TransactorMock)
	transactor.On("WithinTx").Return()
	return transactor
}

func expectStartSession(sessionsRepo *mocks.SessionsRepositoryMock, userUUID string, sessionUUID string) *domain.UserSession {
	created := &domain.UserSession{UUID: sessionUUID, UserUUID: userUUID}
	sessionsRepo.On("DeleteExpiredByUser", userUUID, domain.TokenExpirationRefresh).Return(nil).Once()
	sessionsRepo.On("Create", mock.MatchedBy(func(session domain.UserSession) bool {
		return session.UserUUID == userUUID && session.CurrentJTI != ""
	})).Return(created, nil).Once().Run(func(args mock.Arguments) {
		session := args.Get(0).(domain.UserSession)
		created.CurrentJTI = session.CurrentJTI
		created.ExpiresAt = session.ExpiresAt
	})
	sessionsRepo.On("DeleteOldestBeyond", userUUID, testMaxSessions).Return(nil).Once()
	return created
}

func verifyTestToken(t *testing.T, service domain.AuthService, token string, audience domain.TokenAudience) *domain.VerifiedTokenData {
	t.Helper()
	data, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{Token: token, Audience: audience})
	require.NoError(t, err)
	return data
}

func TestNewAuthService(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
	assert.NotNil(t, service)
}

func TestAuthService_CredentialsLogin(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

	newSessionService := func() (domain.AuthService, *mocks.UsersServiceMock, *mocks.SessionsRepositoryMock, *mocks.TransactorMock) {
		usersService := new(mocks.UsersServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), transactor, services.NewTokenService("test-secret-key", testClock), nil, testSessionMaxAge, testMaxSessions, testClock)
		return service, usersService, sessionsRepo, transactor
	}

	t.Run("success", func(t *testing.T) {
		service, usersService, sessionsRepo, transactor := newSessionService()
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
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
		session := expectStartSession(sessionsRepo, user.UUID, "session-uuid")

		tokens, err := service.CredentialsLogin(context.Background(), dto)

		require.NoError(t, err)
		access := verifyTestToken(t, service, tokens.AccessToken, domain.TokenAudienceAccess)
		assert.Equal(t, user.UUID, access.Subject)
		assert.Equal(t, domain.RoleAdmin, access.Role)
		assert.Equal(t, "session-uuid", access.SessionID)
		assert.Empty(t, access.ID)
		refresh := verifyTestToken(t, service, tokens.RefreshToken, domain.TokenAudienceRefresh)
		assert.Equal(t, "session-uuid", refresh.SessionID)
		assert.NotEmpty(t, session.CurrentJTI)
		assert.Equal(t, session.CurrentJTI, refresh.ID)
		assert.Equal(t, testNow.Add(testSessionMaxAge).Unix(), session.ExpiresAt)
		usersService.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
		transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})

	t.Run("success - each login creates a new session", func(t *testing.T) {
		service, usersService, sessionsRepo, _ := newSessionService()
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		user := &domain.User{UUID: "user-uuid-multi", Email: "multi@example.com", PasswordHash: string(hashedPassword)}
		dto := domain.CredentialsLoginDTO{Email: user.Email, Password: password}
		usersService.On("GetByEmail", dto.Email).Return(user, nil).Twice()
		first := expectStartSession(sessionsRepo, user.UUID, "session-1")

		firstTokens, err := service.CredentialsLogin(context.Background(), dto)
		require.NoError(t, err)
		second := expectStartSession(sessionsRepo, user.UUID, "session-2")
		secondTokens, err := service.CredentialsLogin(context.Background(), dto)
		require.NoError(t, err)

		assert.NotEqual(t, first.CurrentJTI, second.CurrentJTI)
		assert.Equal(t, "session-1", verifyTestToken(t, service, firstTokens.RefreshToken, domain.TokenAudienceRefresh).SessionID)
		assert.Equal(t, "session-2", verifyTestToken(t, service, secondTokens.RefreshToken, domain.TokenAudienceRefresh).SessionID)
		sessionsRepo.AssertExpectations(t)
	})

	storeFailures := []struct {
		name   string
		expect func(*mocks.SessionsRepositoryMock, string, error)
	}{
		{"cleaning expired sessions", func(repo *mocks.SessionsRepositoryMock, userUUID string, err error) {
			repo.On("DeleteExpiredByUser", userUUID, domain.TokenExpirationRefresh).Return(err).Once()
		}},
		{"creating the session", func(repo *mocks.SessionsRepositoryMock, userUUID string, err error) {
			repo.On("DeleteExpiredByUser", userUUID, domain.TokenExpirationRefresh).Return(nil).Once()
			repo.On("Create", mock.Anything).Return(nil, err).Once()
		}},
		{"trimming to the cap", func(repo *mocks.SessionsRepositoryMock, userUUID string, err error) {
			repo.On("DeleteExpiredByUser", userUUID, domain.TokenExpirationRefresh).Return(nil).Once()
			repo.On("Create", mock.Anything).Return(&domain.UserSession{UUID: "session-uuid", UserUUID: userUUID}, nil).Once()
			repo.On("DeleteOldestBeyond", userUUID, testMaxSessions).Return(err).Once()
		}},
	}
	for _, tc := range storeFailures {
		t.Run("error - session store failure when "+tc.name, func(t *testing.T) {
			service, usersService, sessionsRepo, _ := newSessionService()
			password := "password123"
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			user := &domain.User{UUID: "user-uuid-store-failure", Email: "store@example.com", PasswordHash: string(hashedPassword)}
			usersService.On("GetByEmail", user.Email).Return(user, nil).Once()
			tc.expect(sessionsRepo, user.UUID, errors.New("db down"))

			tokens, err := service.CredentialsLogin(context.Background(), domain.CredentialsLoginDTO{Email: user.Email, Password: password})

			var internalErr *domain.InternalServerError
			assert.ErrorAs(t, err, &internalErr)
			assert.Empty(t, tokens)
			sessionsRepo.AssertExpectations(t)
		})
	}

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
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

	t.Run("success", func(t *testing.T) {
		userUUID := "user-uuid-123"
		claims := jwt.MapClaims{
			"sub": userUUID,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
			"aud": domain.TokenAudienceAccess,
			"sid": "session-uuid",
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
		assert.Equal(t, "session-uuid", result.SessionID)
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

func refreshClaims(userUUID string, sid any, jti any) jwt.MapClaims {
	claims := jwt.MapClaims{
		"sub": userUUID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"aud": domain.TokenAudienceRefresh,
	}
	if sid != nil {
		claims["sid"] = sid
	}
	if jti != nil {
		claims["jti"] = jti
	}
	return claims
}

func TestAuthService_RefreshToken(t *testing.T) {
	const (
		userUUID    = "user-uuid-123"
		sessionUUID = "session-uuid"
		currentJTI  = "current-jti"
	)
	activeSession := func() *domain.UserSession {
		return &domain.UserSession{
			UUID:       sessionUUID,
			UserUUID:   userUUID,
			CurrentJTI: currentJTI,
			ExpiresAt:  time.Now().Add(time.Hour).Unix(),
		}
	}

	newService := func() (domain.AuthService, *mocks.UsersServiceMock, *mocks.SessionsRepositoryMock) {
		usersService := new(mocks.UsersServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		service := services.NewAuthService(usersService, nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		return service, usersService, sessionsRepo
	}
	refresh := func(service domain.AuthService, token string) (domain.AuthTokens, error) {
		return service.RefreshToken(context.Background(), domain.RefreshTokenDTO{RefreshToken: token})
	}

	t.Run("success - keeps the session and rotates the jti", func(t *testing.T) {
		service, usersService, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		var nextJTI string
		sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(nil).Once().Run(func(args mock.Arguments) {
			nextJTI = args.String(3)
		})
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID, Role: domain.RoleAdmin}, nil).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		require.NoError(t, err)
		access := verifyTestToken(t, service, tokens.AccessToken, domain.TokenAudienceAccess)
		assert.Equal(t, userUUID, access.Subject)
		assert.Equal(t, domain.RoleAdmin, access.Role)
		assert.Equal(t, sessionUUID, access.SessionID)
		next := verifyTestToken(t, service, tokens.RefreshToken, domain.TokenAudienceRefresh)
		assert.Equal(t, sessionUUID, next.SessionID)
		assert.NotEmpty(t, nextJTI)
		assert.NotEqual(t, currentJTI, nextJTI)
		assert.Equal(t, nextJTI, next.ID)
		usersService.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
		sessionsRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	})

	for name, failAt := range map[string]domain.TokenAudience{
		"access token generation fails":  domain.TokenAudienceAccess,
		"refresh token generation fails": domain.TokenAudienceRefresh,
	} {
		t.Run("error - "+name, func(t *testing.T) {
			usersService := new(mocks.UsersServiceMock)
			sessionsRepo := new(mocks.SessionsRepositoryMock)
			tokens := new(mocks.TokenServiceMock)
			service := services.NewAuthService(usersService, nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), tokens, nil, testSessionMaxAge, testMaxSessions, time.Now)
			tokens.On("VerifyToken", mock.Anything).Return(&domain.VerifiedTokenData{Subject: userUUID, SessionID: sessionUUID, ID: currentJTI}, nil).Once()
			sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
			sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(nil).Once()
			usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(&domain.User{UUID: userUUID}, nil).Once()
			genErr := errors.New("signing failed")
			tokens.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool { return dto.Audience == failAt })).Return("", genErr).Once()
			if failAt == domain.TokenAudienceRefresh {
				tokens.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool { return dto.Audience == domain.TokenAudienceAccess })).Return("access", nil).Once()
			}

			result, err := refresh(service, "refresh-token")

			var internalErr *domain.InternalServerError
			require.ErrorAs(t, err, &internalErr)
			assert.Equal(t, "auth.refreshToken.tokenGenerationFailed", err.Error())
			assert.ErrorIs(t, err, genErr)
			assert.Empty(t, result)
		})
	}

	t.Run("error - session not found", func(t *testing.T) {
		service, _, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(nil, domain.NewNotFoundError("sessions.notFound")).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
		sessionsRepo.AssertNotCalled(t, "RotateJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - session lookup internal error is returned", func(t *testing.T) {
		service, _, sessionsRepo := newService()
		lookupErr := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(nil, lookupErr).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, lookupErr)
		assert.Empty(t, tokens)
	})

	t.Run("error - expired session is deleted", func(t *testing.T) {
		service, _, sessionsRepo := newService()
		expired := activeSession()
		expired.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(expired, nil).Once()
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(nil).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
		sessionsRepo.AssertExpectations(t)
		sessionsRepo.AssertNotCalled(t, "RotateJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - session expiring at the current instant is deleted", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		tokens := new(mocks.TokenServiceMock)
		service := services.NewAuthService(usersService, nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), tokens, nil, testSessionMaxAge, testMaxSessions, testClock)
		tokens.On("VerifyToken", mock.Anything).Return(&domain.VerifiedTokenData{Subject: userUUID, SessionID: sessionUUID, ID: currentJTI}, nil).Once()
		expiring := activeSession()
		expiring.ExpiresAt = testNow.Unix()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(expiring, nil).Once()
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(nil).Once()

		result, err := refresh(service, "refresh-token")

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, result)
		sessionsRepo.AssertExpectations(t)
	})

	t.Run("success - session expiring one second from now is still rotated", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		tokens := new(mocks.TokenServiceMock)
		service := services.NewAuthService(usersService, nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), tokens, nil, testSessionMaxAge, testMaxSessions, testClock)
		tokens.On("VerifyToken", mock.Anything).Return(&domain.VerifiedTokenData{Subject: userUUID, SessionID: sessionUUID, ID: currentJTI}, nil).Once()
		expiring := activeSession()
		expiring.ExpiresAt = testNow.Add(time.Second).Unix()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(expiring, nil).Once()
		rotateErr := errors.New("rotate failed")
		sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(rotateErr).Once()

		_, err := refresh(service, "refresh-token")

		assert.ErrorIs(t, err, rotateErr)
		sessionsRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	})

	t.Run("error - reused jti deletes the session", func(t *testing.T) {
		service, usersService, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(nil).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, "stale-jti")))

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
		sessionsRepo.AssertExpectations(t)
		sessionsRepo.AssertNotCalled(t, "RotateJTI", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		usersService.AssertNotCalled(t, "GetByUUID", mock.Anything, mock.Anything)
	})

	t.Run("error - lost rotation race deletes the session", func(t *testing.T) {
		service, usersService, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(domain.NewNotFoundError("sessions.notFound")).Once()
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(nil).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
		sessionsRepo.AssertExpectations(t)
		usersService.AssertNotCalled(t, "GetByUUID", mock.Anything, mock.Anything)
	})

	t.Run("error - session revocation failure is returned", func(t *testing.T) {
		service, _, sessionsRepo := newService()
		deleteErr := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(deleteErr).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, "stale-jti")))

		assert.ErrorIs(t, err, deleteErr)
		assert.Empty(t, tokens)
	})

	t.Run("error - rotation internal error is returned", func(t *testing.T) {
		service, _, sessionsRepo := newService()
		rotateErr := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(rotateErr).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, rotateErr)
		assert.Empty(t, tokens)
		sessionsRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	})

	t.Run("error - deleted user", func(t *testing.T) {
		service, usersService, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(nil).Once()
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(nil, domain.NewNotFoundError("users.notFound")).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, tokens)
	})

	t.Run("error - user lookup internal error is returned", func(t *testing.T) {
		service, usersService, sessionsRepo := newService()
		lookupErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession(), nil).Once()
		sessionsRepo.On("RotateJTI", userUUID, sessionUUID, currentJTI, mock.AnythingOfType("string")).Return(nil).Once()
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(nil, lookupErr).Once()

		tokens, err := refresh(service, signTestToken(t, refreshClaims(userUUID, sessionUUID, currentJTI)))

		assert.ErrorIs(t, err, lookupErr)
		assert.Empty(t, tokens)
	})

	claimCases := []struct {
		name string
		sid  any
		jti  any
	}{
		{"missing jti", sessionUUID, nil},
		{"empty jti", sessionUUID, ""},
		{"non-string jti", sessionUUID, 123},
		{"missing sid", nil, currentJTI},
		{"non-string sid", 123, currentJTI},
	}
	for _, tc := range claimCases {
		t.Run("error - "+tc.name, func(t *testing.T) {
			service, _, sessionsRepo := newService()

			var tokens domain.AuthTokens
			var err error
			assert.NotPanics(t, func() {
				tokens, err = refresh(service, signTestToken(t, refreshClaims(userUUID, tc.sid, tc.jti)))
			})

			assert.ErrorIs(t, err, services.ErrInvalidToken)
			assert.Empty(t, tokens)
			sessionsRepo.AssertNotCalled(t, "FindByUUID", mock.Anything, mock.Anything)
		})
	}

	t.Run("error - invalid refresh token", func(t *testing.T) {
		service, _, _ := newService()

		tokens, err := refresh(service, "invalid-token")

		assert.Error(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("error - expired refresh token", func(t *testing.T) {
		service, _, sessionsRepo := newService()
		claims := refreshClaims(userUUID, sessionUUID, currentJTI)
		claims["exp"] = time.Now().Add(-time.Hour).Unix()

		tokens, err := refresh(service, signTestToken(t, claims))

		assert.Error(t, err)
		assert.Empty(t, tokens)
		sessionsRepo.AssertNotCalled(t, "FindByUUID", mock.Anything, mock.Anything)
	})
}

func TestAuthService_Logout(t *testing.T) {
	const (
		userUUID    = "user-uuid-123"
		sessionUUID = "session-uuid"
	)

	newService := func() (domain.AuthService, *mocks.SessionsRepositoryMock) {
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		service := services.NewAuthService(new(mocks.UsersServiceMock), nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		return service, sessionsRepo
	}

	t.Run("success - deletes only the given session", func(t *testing.T) {
		service, sessionsRepo := newService()
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(nil).Once()

		err := service.Logout(context.Background(), userUUID, sessionUUID)

		assert.NoError(t, err)
		sessionsRepo.AssertExpectations(t)
		sessionsRepo.AssertNumberOfCalls(t, "Delete", 1)
	})

	t.Run("error - delete failure is returned", func(t *testing.T) {
		service, sessionsRepo := newService()
		deleteErr := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		sessionsRepo.On("Delete", userUUID, sessionUUID).Return(deleteErr).Once()

		err := service.Logout(context.Background(), userUUID, sessionUUID)

		assert.ErrorIs(t, err, deleteErr)
	})
}

func TestAuthService_LogoutOthers(t *testing.T) {
	const (
		userUUID    = "user-uuid-123"
		sessionUUID = "session-uuid"
	)

	newService := func() (domain.AuthService, *mocks.SessionsRepositoryMock) {
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		service := services.NewAuthService(new(mocks.UsersServiceMock), nil, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		return service, sessionsRepo
	}
	activeSession := &domain.UserSession{UUID: sessionUUID, UserUUID: userUUID, ExpiresAt: time.Now().Add(time.Hour).Unix()}

	t.Run("success - keeps the given session", func(t *testing.T) {
		service, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession, nil).Once()
		sessionsRepo.On("DeleteOthersByUser", userUUID, sessionUUID).Return(nil).Once()

		err := service.LogoutOthers(context.Background(), userUUID, sessionUUID)

		assert.NoError(t, err)
		sessionsRepo.AssertExpectations(t)
	})

	t.Run("error - session not found", func(t *testing.T) {
		service, sessionsRepo := newService()
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(nil, domain.NewNotFoundError("sessions.notFound")).Once()

		err := service.LogoutOthers(context.Background(), userUUID, sessionUUID)

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		sessionsRepo.AssertNotCalled(t, "DeleteOthersByUser", mock.Anything, mock.Anything)
	})

	t.Run("error - session expired", func(t *testing.T) {
		service, sessionsRepo := newService()
		expired := &domain.UserSession{UUID: sessionUUID, UserUUID: userUUID, ExpiresAt: time.Now().Add(-time.Minute).Unix()}
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(expired, nil).Once()

		err := service.LogoutOthers(context.Background(), userUUID, sessionUUID)

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		sessionsRepo.AssertNotCalled(t, "DeleteOthersByUser", mock.Anything, mock.Anything)
	})

	t.Run("error - lookup failure is returned", func(t *testing.T) {
		service, sessionsRepo := newService()
		lookupErr := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(nil, lookupErr).Once()

		err := service.LogoutOthers(context.Background(), userUUID, sessionUUID)

		assert.ErrorIs(t, err, lookupErr)
		sessionsRepo.AssertNotCalled(t, "DeleteOthersByUser", mock.Anything, mock.Anything)
	})

	t.Run("error - delete failure is returned", func(t *testing.T) {
		service, sessionsRepo := newService()
		deleteErr := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		sessionsRepo.On("FindByUUID", userUUID, sessionUUID).Return(activeSession, nil).Once()
		sessionsRepo.On("DeleteOthersByUser", userUUID, sessionUUID).Return(deleteErr).Once()

		err := service.LogoutOthers(context.Background(), userUUID, sessionUUID)

		assert.ErrorIs(t, err, deleteErr)
	})
}

func TestAuthService_GenerateToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

	t.Run("success with access token audience", func(t *testing.T) {
		dto := domain.GenerateTokenDTO{
			Subject:   "user-uuid-123",
			Audience:  domain.TokenAudienceAccess,
			SessionID: "session-uuid",
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
			Subject:   "user-uuid-123",
			Audience:  domain.TokenAudienceAccess,
			SessionID: "session-uuid",
			Role:      domain.RoleAdmin,
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
			Subject:   "user-uuid-456",
			Audience:  domain.TokenAudienceRefresh,
			SessionID: "session-uuid",
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
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
		service := services.NewAuthService(new(mocks.UsersServiceMock), nil, new(mocks.AuthRepositoryMock), new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
	service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		service := services.NewAuthService(usersService, nil, authRepo, sessionsRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: "test@example.com"}
		userOAuthProvider := &domain.UserOAuthProvider{UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID}
		user := &domain.User{UUID: userUUID, Email: "test@example.com", Name: "Test User"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(userOAuthProvider, nil).Once()
		usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(user, nil).Once()
		session := expectStartSession(sessionsRepo, userUUID, "session-uuid")

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, userUUID, result.User.UUID)
		assert.Equal(t, redirectURI, result.RedirectURI)
		assert.NotEmpty(t, result.Tokens.AccessToken)
		assert.NotEmpty(t, result.Tokens.RefreshToken)
		refresh := verifyTestToken(t, service, result.Tokens.RefreshToken, domain.TokenAudienceRefresh)
		assert.Equal(t, "session-uuid", refresh.SessionID)
		assert.Equal(t, session.CurrentJTI, refresh.ID)
		assert.Equal(t, "session-uuid", verifyTestToken(t, service, result.Tokens.AccessToken, domain.TokenAudienceAccess).SessionID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
		transactor.AssertNumberOfCalls(t, "WithinTx", 2)
	})

	t.Run("success - link to existing user by email (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		emails := new(mocks.EmailVerificationServiceMock)
		service := services.NewAuthService(usersService, nil, authRepo, sessionsRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), emails, testSessionMaxAge, testMaxSessions, time.Now)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}
		user := &domain.User{UUID: userUUID, Email: email, Name: "Test User"}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(user, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == userUUID && p.Provider == provider && p.ProviderUserID == providerUserID
		})).Return(&domain.UserOAuthProvider{UUID: "link-uuid", Provider: provider}, nil).Once()
		emails.On("SendOAuthLinkedNotice", email, domain.OAuthLinkRevert{UserUUID: userUUID, LinkUUID: "link-uuid", Provider: provider}).Return(nil).Once()
		expectStartSession(sessionsRepo, userUUID, "session-uuid")

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, userUUID, result.User.UUID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
		emails.AssertExpectations(t)
	})

	t.Run("success - create new user (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		service := services.NewAuthService(usersService, nil, authRepo, sessionsRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email}).Return(newUser, nil).Once()
		authRepo.On("CreateUserOAuthProvider", mock.MatchedBy(func(p domain.UserOAuthProvider) bool {
			return p.UserUUID == newUserUUID && p.Provider == provider
		})).Return(&domain.UserOAuthProvider{}, nil).Once()
		expectStartSession(sessionsRepo, newUserUUID, "session-uuid")

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, newUserUUID, result.User.UUID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
		transactor.AssertNumberOfCalls(t, "WithinTx", 2)
	})

	t.Run("error - create user fails (Case 3)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		providerMock := new(mocks.OAuthProviderMock)

		email := "new@example.com"
		name := "New User"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: name, Email: email, EmailVerified: true}

		oauthProviderRegistry.On("Get", provider).Return(providerMock, nil).Once()
		providerMock.On("GetUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), code, codeVerifier).Return(userInfo, nil).Once()
		authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, domain.NewNotFoundError("auth.oauthProvider.notFound")).Once()
		usersService.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("user.notFound")).Once()
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email}).Return(nil, errors.New("db error")).Once()

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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
		usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: name, Email: email}).Return(newUser, nil).Once()
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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		providerMock := new(mocks.OAuthProviderMock)

		userUUID := "user-uuid"
		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}
		user := &domain.User{UUID: userUUID, Email: email}

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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
				service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
				service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)

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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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
		service := services.NewAuthService(usersService, nil, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret, time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		providerMock := new(mocks.OAuthProviderMock)

		email := "test@example.com"
		userInfo := &domain.OAuthProviderUserInfo{ID: providerUserID, Name: "Test User", Email: email, EmailVerified: true}

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

	t.Run("resolve user", testOAuthLoginResolveUser)
}

func TestAuthService_VerifyOAuthState(t *testing.T) {
	const (
		provider    = domain.OAuthProviderGoogle
		redirectURI = "http://localhost:3000/callback"
		nonce       = "browser-nonce"
	)

	newService := func() domain.AuthService {
		return services.NewAuthService(new(mocks.UsersServiceMock), nil, new(mocks.AuthRepositoryMock), new(mocks.SessionsRepositoryMock), new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
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

func TestAuthService_CompleteSignup(t *testing.T) {
	const (
		pendingUUID = "pending-uuid"
		code        = "123456"
		userUUID    = "user-uuid"
		sessionUUID = "session-uuid"
	)
	pending := &domain.PendingSignup{
		UUID:         pendingUUID,
		Kind:         domain.PendingSignupKindCredentials,
		Name:         "New User",
		Email:        "new@example.com",
		PasswordHash: "bcrypt-hash",
	}
	newUserDTO := domain.NewUserDTO{Name: "New User", Email: "new@example.com", PasswordHash: "bcrypt-hash"}

	newSignupService := func() (domain.AuthService, *mocks.UsersServiceMock, *mocks.PendingSignupServiceMock, *mocks.SessionsRepositoryMock, *mocks.TransactorMock) {
		usersService := new(mocks.UsersServiceMock)
		pendingSignups := new(mocks.PendingSignupServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, pendingSignups, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), transactor, services.NewTokenService("test-secret-key", time.Now), nil, testSessionMaxAge, testMaxSessions, time.Now)
		return service, usersService, pendingSignups, sessionsRepo, transactor
	}

	t.Run("success", func(t *testing.T) {
		service, usersService, pendingSignups, sessionsRepo, transactor := newSignupService()
		user := &domain.User{UUID: userUUID, Name: "New User", Email: "new@example.com", Role: domain.RoleUser}
		pendingSignups.On("Attempt", pendingUUID, code).Return(nil).Once()
		pendingSignups.On("Consume", pendingUUID, code).Return(pending, nil).Once()
		usersService.On("Create", newUserDTO).Return(user, nil).Once()
		expectStartSession(sessionsRepo, userUUID, sessionUUID)

		result, err := service.CompleteSignup(context.Background(), pendingUUID, code)

		require.NoError(t, err)
		assert.Equal(t, user, result.User)
		access := verifyTestToken(t, service, result.Tokens.AccessToken, domain.TokenAudienceAccess)
		assert.Equal(t, userUUID, access.Subject)
		assert.Equal(t, sessionUUID, access.SessionID)
		verifyTestToken(t, service, result.Tokens.RefreshToken, domain.TokenAudienceRefresh)
		pendingSignups.AssertExpectations(t)
		usersService.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
		transactor.AssertCalled(t, "WithinTx")
	})

	t.Run("error - wrong code never reaches the transaction", func(t *testing.T) {
		service, usersService, pendingSignups, _, transactor := newSignupService()
		pendingSignups.On("Attempt", pendingUUID, code).Return(domain.ErrSignupInvalidCode).Once()

		result, err := service.CompleteSignup(context.Background(), pendingUUID, code)

		assert.Equal(t, domain.ErrSignupInvalidCode, err)
		assert.Nil(t, result)
		transactor.AssertNotCalled(t, "WithinTx")
		pendingSignups.AssertNotCalled(t, "Consume", mock.Anything, mock.Anything)
		usersService.AssertNotCalled(t, "Create", mock.Anything)
	})

	t.Run("error - already consumed", func(t *testing.T) {
		service, usersService, pendingSignups, _, _ := newSignupService()
		pendingSignups.On("Attempt", pendingUUID, code).Return(nil).Once()
		pendingSignups.On("Consume", pendingUUID, code).Return(nil, domain.ErrSignupNoPending).Once()

		result, err := service.CompleteSignup(context.Background(), pendingUUID, code)

		assert.Equal(t, domain.ErrSignupNoPending, err)
		assert.Nil(t, result)
		usersService.AssertNotCalled(t, "Create", mock.Anything)
	})

	t.Run("error - email taken meanwhile", func(t *testing.T) {
		service, usersService, pendingSignups, sessionsRepo, _ := newSignupService()
		pendingSignups.On("Attempt", pendingUUID, code).Return(nil).Once()
		pendingSignups.On("Consume", pendingUUID, code).Return(pending, nil).Once()
		usersService.On("Create", newUserDTO).Return(nil, domain.NewConflictError("users.email.conflict")).Once()

		result, err := service.CompleteSignup(context.Background(), pendingUUID, code)

		var conflictErr *domain.ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Nil(t, result)
		sessionsRepo.AssertNotCalled(t, "Create", mock.Anything)
	})

	t.Run("error - session start fails", func(t *testing.T) {
		service, usersService, pendingSignups, sessionsRepo, _ := newSignupService()
		pendingSignups.On("Attempt", pendingUUID, code).Return(nil).Once()
		pendingSignups.On("Consume", pendingUUID, code).Return(pending, nil).Once()
		usersService.On("Create", newUserDTO).Return(&domain.User{UUID: userUUID}, nil).Once()
		sessionsRepo.On("DeleteExpiredByUser", userUUID, domain.TokenExpirationRefresh).Return(errors.New("db down")).Once()

		result, err := service.CompleteSignup(context.Background(), pendingUUID, code)

		var internalErr *domain.InternalServerError
		require.ErrorAs(t, err, &internalErr)
		assert.Equal(t, "auth.signup.tokenGenerationFailed", err.Error())
		assert.Nil(t, result)
	})

	t.Run("oauth", func(t *testing.T) {
		const (
			provider       = domain.OAuthProviderGitHub
			providerUserID = "gh-1"
		)
		oauthPending := &domain.PendingSignup{
			UUID: pendingUUID, Kind: domain.PendingSignupKindOAuth, Name: "OAuth User", Email: "new@example.com",
			Provider: provider, ProviderUserID: providerUserID,
		}
		linkNotFound := domain.NewNotFoundError("auth.oauthProvider.notFound")
		link := domain.UserOAuthProvider{UserUUID: userUUID, Provider: provider, ProviderUserID: providerUserID, ProviderEmail: "new@example.com"}

		type oauthFixture struct {
			service        domain.AuthService
			usersService   *mocks.UsersServiceMock
			pendingSignups *mocks.PendingSignupServiceMock
			authRepo       *mocks.AuthRepositoryMock
			sessionsRepo   *mocks.SessionsRepositoryMock
			transactor     *mocks.TransactorMock
			emails         *mocks.EmailVerificationServiceMock
		}
		newOAuthFixture := func() oauthFixture {
			f := oauthFixture{
				usersService:   new(mocks.UsersServiceMock),
				pendingSignups: new(mocks.PendingSignupServiceMock),
				authRepo:       new(mocks.AuthRepositoryMock),
				sessionsRepo:   new(mocks.SessionsRepositoryMock),
				transactor:     newTransactorMock(),
				emails:         new(mocks.EmailVerificationServiceMock),
			}
			f.service = services.NewAuthService(f.usersService, f.pendingSignups, f.authRepo, f.sessionsRepo, new(mocks.OAuthProviderRegistryMock), f.transactor, services.NewTokenService("test-secret-key", time.Now), f.emails, testSessionMaxAge, testMaxSessions, time.Now)
			f.pendingSignups.On("Attempt", pendingUUID, code).Return(nil).Once()
			return f
		}

		t.Run("success - provider already linked signs in to the linked user", func(t *testing.T) {
			f := newOAuthFixture()
			user := &domain.User{UUID: userUUID, Email: "other@example.com"}
			f.pendingSignups.On("Consume", pendingUUID, code).Return(oauthPending, nil).Once()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(&domain.UserOAuthProvider{UserUUID: userUUID}, nil).Once()
			f.usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(user, nil).Once()
			expectStartSession(f.sessionsRepo, userUUID, sessionUUID)

			result, err := f.service.CompleteSignup(context.Background(), pendingUUID, code)

			require.NoError(t, err)
			assert.Equal(t, user, result.User)
			assert.NotEmpty(t, result.Tokens.AccessToken)
			f.authRepo.AssertNotCalled(t, "CreateUserOAuthProvider", mock.Anything)
			f.usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
		})

		t.Run("success - links into the user that owns the email", func(t *testing.T) {
			f := newOAuthFixture()
			user := &domain.User{UUID: userUUID, Email: "new@example.com"}
			f.pendingSignups.On("Consume", pendingUUID, code).Return(oauthPending, nil).Once()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, linkNotFound).Once()
			f.usersService.On("GetByEmail", "new@example.com").Return(user, nil).Once()
			f.authRepo.On("CreateUserOAuthProvider", link).Return(&domain.UserOAuthProvider{}, nil).Once()
			expectStartSession(f.sessionsRepo, userUUID, sessionUUID)

			result, err := f.service.CompleteSignup(context.Background(), pendingUUID, code)

			require.NoError(t, err)
			assert.Equal(t, user, result.User)
			f.authRepo.AssertExpectations(t)
			f.usersService.AssertNotCalled(t, "CreateOAuth", mock.Anything)
			f.emails.AssertNotCalled(t, "SendOAuthLinkedNotice", mock.Anything, mock.Anything)
		})

		t.Run("success - creates the user and links", func(t *testing.T) {
			f := newOAuthFixture()
			user := &domain.User{UUID: userUUID, Email: "new@example.com"}
			f.pendingSignups.On("Consume", pendingUUID, code).Return(oauthPending, nil).Once()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, linkNotFound).Once()
			f.usersService.On("GetByEmail", "new@example.com").Return(nil, domain.NewNotFoundError("user.notFound")).Once()
			f.usersService.On("CreateOAuth", domain.CreateOAuthUserDTO{Name: "OAuth User", Email: "new@example.com"}).Return(user, nil).Once()
			f.authRepo.On("CreateUserOAuthProvider", link).Return(&domain.UserOAuthProvider{}, nil).Once()
			expectStartSession(f.sessionsRepo, userUUID, sessionUUID)

			result, err := f.service.CompleteSignup(context.Background(), pendingUUID, code)

			require.NoError(t, err)
			assert.Equal(t, user, result.User)
			f.usersService.AssertExpectations(t)
			f.authRepo.AssertExpectations(t)
			f.transactor.AssertNumberOfCalls(t, "WithinTx", 2)
		})

		t.Run("success - a concurrent link is found by one retry in a fresh transaction", func(t *testing.T) {
			f := newOAuthFixture()
			user := &domain.User{UUID: userUUID, Email: "new@example.com"}
			f.pendingSignups.On("Consume", pendingUUID, code).Return(oauthPending, nil).Twice()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, linkNotFound).Once()
			f.usersService.On("GetByEmail", "new@example.com").Return(nil, domain.NewNotFoundError("user.notFound")).Once()
			f.usersService.On("CreateOAuth", mock.Anything).Return(nil, domain.NewConflictError("users.email.conflict")).Once()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(&domain.UserOAuthProvider{UserUUID: userUUID}, nil).Once()
			f.usersService.On("GetByUUID", domain.Actor{UUID: userUUID}, userUUID).Return(user, nil).Once()
			expectStartSession(f.sessionsRepo, userUUID, sessionUUID)

			result, err := f.service.CompleteSignup(context.Background(), pendingUUID, code)

			require.NoError(t, err)
			assert.Equal(t, user, result.User)
			f.transactor.AssertNumberOfCalls(t, "WithinTx", 3)
			f.pendingSignups.AssertNumberOfCalls(t, "Attempt", 1)
		})

		t.Run("error - a persistent conflict (reservation) is returned after one retry", func(t *testing.T) {
			f := newOAuthFixture()
			f.pendingSignups.On("Consume", pendingUUID, code).Return(oauthPending, nil).Twice()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, linkNotFound).Twice()
			f.usersService.On("GetByEmail", "new@example.com").Return(nil, domain.NewNotFoundError("user.notFound")).Twice()
			f.usersService.On("CreateOAuth", mock.Anything).Return(nil, domain.NewConflictError("users.email.conflict")).Twice()

			result, err := f.service.CompleteSignup(context.Background(), pendingUUID, code)

			var conflictErr *domain.ConflictError
			require.ErrorAs(t, err, &conflictErr)
			assert.Equal(t, "users.email.conflict", err.Error())
			assert.Nil(t, result)
			f.transactor.AssertNumberOfCalls(t, "WithinTx", 2)
			f.sessionsRepo.AssertNotCalled(t, "Create", mock.Anything)
		})

		t.Run("error - link failure other than a conflict is not retried", func(t *testing.T) {
			f := newOAuthFixture()
			linkErr := errors.New("link failed")
			f.pendingSignups.On("Consume", pendingUUID, code).Return(oauthPending, nil).Once()
			f.authRepo.On("GetUserOAuthProviderByProviderAndProviderUserID", provider, providerUserID).Return(nil, linkNotFound).Once()
			f.usersService.On("GetByEmail", "new@example.com").Return(nil, domain.NewNotFoundError("user.notFound")).Once()
			f.usersService.On("CreateOAuth", mock.Anything).Return(&domain.User{UUID: userUUID}, nil).Once()
			f.authRepo.On("CreateUserOAuthProvider", mock.Anything).Return(nil, linkErr).Once()

			result, err := f.service.CompleteSignup(context.Background(), pendingUUID, code)

			assert.Equal(t, linkErr, err)
			assert.Nil(t, result)
			f.transactor.AssertNumberOfCalls(t, "WithinTx", 1)
		})
	})

	t.Run("error - credentials conflict is not retried", func(t *testing.T) {
		service, usersService, pendingSignups, _, transactor := newSignupService()
		pendingSignups.On("Attempt", pendingUUID, code).Return(nil).Once()
		pendingSignups.On("Consume", pendingUUID, code).Return(pending, nil).Once()
		usersService.On("Create", newUserDTO).Return(nil, domain.NewConflictError("users.email.conflict")).Once()

		_, err := service.CompleteSignup(context.Background(), pendingUUID, code)

		require.Error(t, err)
		transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})
}

func TestAuthService_RevertOAuthLink(t *testing.T) {
	const (
		token    = "revert-token"
		userUUID = "user-uuid"
		linkUUID = "link-uuid"
	)
	revert := &domain.OAuthLinkRevert{UserUUID: userUUID, LinkUUID: linkUUID, Provider: domain.OAuthProviderGoogle}

	type fixture struct {
		service      domain.AuthService
		emails       *mocks.EmailVerificationServiceMock
		authRepo     *mocks.AuthRepositoryMock
		sessionsRepo *mocks.SessionsRepositoryMock
		transactor   *mocks.TransactorMock
	}
	newFixture := func() fixture {
		f := fixture{
			emails:       new(mocks.EmailVerificationServiceMock),
			authRepo:     new(mocks.AuthRepositoryMock),
			sessionsRepo: new(mocks.SessionsRepositoryMock),
			transactor:   newTransactorMock(),
		}
		f.service = services.NewAuthService(new(mocks.UsersServiceMock), nil, f.authRepo, f.sessionsRepo, new(mocks.OAuthProviderRegistryMock), f.transactor, services.NewTokenService("test-secret-key", time.Now), f.emails, testSessionMaxAge, testMaxSessions, time.Now)
		return f
	}

	t.Run("success - deletes the link and every session in one transaction", func(t *testing.T) {
		f := newFixture()
		f.emails.On("VerifyOAuthLinkRevertToken", token).Return(revert, nil).Once()
		f.authRepo.On("DeleteUserOAuthProviderOfUser", userUUID, linkUUID).Return(true, nil).Once()
		f.sessionsRepo.On("DeleteAllByUser", userUUID).Return(nil).Once()

		got, err := f.service.RevertOAuthLink(context.Background(), token)

		require.NoError(t, err)
		assert.Equal(t, userUUID, got)
		f.authRepo.AssertExpectations(t)
		f.sessionsRepo.AssertExpectations(t)
		f.transactor.AssertNumberOfCalls(t, "WithinTx", 1)
	})

	t.Run("error - invalid token", func(t *testing.T) {
		f := newFixture()
		f.emails.On("VerifyOAuthLinkRevertToken", token).Return(nil, services.ErrInvalidToken).Once()

		got, err := f.service.RevertOAuthLink(context.Background(), token)

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, got)
		f.transactor.AssertNotCalled(t, "WithinTx")
		f.authRepo.AssertNotCalled(t, "DeleteUserOAuthProviderOfUser", mock.Anything, mock.Anything)
	})

	t.Run("error - stale token when the link is already gone", func(t *testing.T) {
		f := newFixture()
		f.emails.On("VerifyOAuthLinkRevertToken", token).Return(revert, nil).Once()
		f.authRepo.On("DeleteUserOAuthProviderOfUser", userUUID, linkUUID).Return(false, nil).Once()

		got, err := f.service.RevertOAuthLink(context.Background(), token)

		var unauthorizedErr *domain.UnauthorizedError
		require.ErrorAs(t, err, &unauthorizedErr)
		assert.Equal(t, "auth.oauthLink.staleToken", err.Error())
		assert.Empty(t, got)
		f.sessionsRepo.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
	})

	t.Run("error - repository error deleting the link", func(t *testing.T) {
		f := newFixture()
		repoErr := errors.New("db down")
		f.emails.On("VerifyOAuthLinkRevertToken", token).Return(revert, nil).Once()
		f.authRepo.On("DeleteUserOAuthProviderOfUser", userUUID, linkUUID).Return(false, repoErr).Once()

		got, err := f.service.RevertOAuthLink(context.Background(), token)

		assert.ErrorIs(t, err, repoErr)
		assert.Empty(t, got)
		f.sessionsRepo.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
	})

	t.Run("error - repository error deleting the sessions", func(t *testing.T) {
		f := newFixture()
		repoErr := errors.New("db down")
		f.emails.On("VerifyOAuthLinkRevertToken", token).Return(revert, nil).Once()
		f.authRepo.On("DeleteUserOAuthProviderOfUser", userUUID, linkUUID).Return(true, nil).Once()
		f.sessionsRepo.On("DeleteAllByUser", userUUID).Return(repoErr).Once()

		got, err := f.service.RevertOAuthLink(context.Background(), token)

		assert.ErrorIs(t, err, repoErr)
		assert.Empty(t, got)
	})
}
