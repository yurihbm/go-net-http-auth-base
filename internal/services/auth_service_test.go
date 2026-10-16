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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
	assert.NotNil(t, service)
}

func TestAuthService_CredentialsLogin(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

	newSessionService := func() (domain.AuthService, *mocks.UsersServiceMock, *mocks.SessionsRepositoryMock, *mocks.TransactorMock) {
		usersService := new(mocks.UsersServiceMock)
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		transactor := newTransactorMock()
		service := services.NewAuthService(usersService, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), transactor, services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
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
		assert.InDelta(t, time.Now().Add(testSessionMaxAge).Unix(), session.ExpiresAt, 5)
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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
		service := services.NewAuthService(usersService, new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(new(mocks.UsersServiceMock), new(mocks.AuthRepositoryMock), sessionsRepo, new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
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

func TestAuthService_GenerateToken(t *testing.T) {
	usersService := new(mocks.UsersServiceMock)
	authRepo := new(mocks.AuthRepositoryMock)
	oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
		service := services.NewAuthService(new(mocks.UsersServiceMock), new(mocks.AuthRepositoryMock), new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
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
	service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)

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
		service := services.NewAuthService(usersService, authRepo, sessionsRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, sessionsRepo, oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		expectStartSession(sessionsRepo, userUUID, "session-uuid")

		state := newState(t, service, string(provider))
		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, userUUID, result.User.UUID)
		usersService.AssertExpectations(t)
		authRepo.AssertExpectations(t)
		sessionsRepo.AssertExpectations(t)
	})

	t.Run("error - email not verified (Case 2)", func(t *testing.T) {
		usersService := new(mocks.UsersServiceMock)
		authRepo := new(mocks.AuthRepositoryMock)
		oauthProviderRegistry := new(mocks.OAuthProviderRegistryMock)
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		sessionsRepo := new(mocks.SessionsRepositoryMock)
		service := services.NewAuthService(usersService, authRepo, sessionsRepo, oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, transactor, services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)

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
				service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)

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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)

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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)

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
				service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)

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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		service := services.NewAuthService(usersService, authRepo, new(mocks.SessionsRepositoryMock), oauthProviderRegistry, newTransactorMock(), services.NewTokenService(jwtSecret), testSessionMaxAge, testMaxSessions)
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
		return services.NewAuthService(new(mocks.UsersServiceMock), new(mocks.AuthRepositoryMock), new(mocks.SessionsRepositoryMock), new(mocks.OAuthProviderRegistryMock), newTransactorMock(), services.NewTokenService("test-secret-key"), testSessionMaxAge, testMaxSessions)
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
