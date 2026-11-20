package repositories_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type failingTrimSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingTrimSessionsRepository) DeleteOldestBeyond(context.Context, string, int) error {
	return r.err
}

func TestCredentialsLogin_Transaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const (
		email    = "login@example.com"
		password = "password123"
	)

	setup := func(t *testing.T, trimErr error) (domain.AuthService, domain.SessionsRepository, *domain.UserSession) {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		require.NoError(t, err)
		user, err := usersRepo.Create(ctx, domain.User{Name: "Login User", Email: email, PasswordHash: string(hash), Role: domain.RoleUser})
		require.NoError(t, err)

		expired := seedSession(t, sessionsRepo, user.UUID, "expired")
		setSessionTimes(t, expired.UUID, time.Now(), time.Now().Add(-time.Minute))

		serviceSessionsRepo := sessionsRepo
		if trimErr != nil {
			serviceSessionsRepo = failingTrimSessionsRepository{SessionsRepository: sessionsRepo, err: trimErr}
		}

		service := services.NewAuthService(
			services.NewUserService(usersRepo, new(mocks.EmailVerificationServiceMock), nil, nil, repositories.NewPostgresTransactor(testDB)),
			repositories.NewAuthPostgresRepository(db),
			serviceSessionsRepo,
			new(mocks.OAuthProviderRegistryMock),
			repositories.NewPostgresTransactor(testDB),
			services.NewTokenService("test-secret-key"),
			30*24*time.Hour,
			10,
		)

		return service, sessionsRepo, expired
	}

	countSessions := func(t *testing.T) int {
		t.Helper()
		var count int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM user_sessions").Scan(&count))
		return count
	}

	t.Run("success", func(t *testing.T) {
		service, sessionsRepo, expired := setup(t, nil)

		tokens, err := service.CredentialsLogin(context.Background(), domain.CredentialsLoginDTO{Email: email, Password: password})

		require.NoError(t, err)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		assert.Equal(t, 1, countSessions(t))
		assert.False(t, sessionExists(t, sessionsRepo, expired.UserUUID, expired.UUID))
	})

	t.Run("error - trimming sessions fails rolls back the login", func(t *testing.T) {
		trimErr := errors.New("trim failed")
		service, sessionsRepo, expired := setup(t, trimErr)

		tokens, err := service.CredentialsLogin(context.Background(), domain.CredentialsLoginDTO{Email: email, Password: password})

		require.Error(t, err)
		assert.ErrorIs(t, err, trimErr)
		assert.Empty(t, tokens.AccessToken)
		assert.Equal(t, 1, countSessions(t))
		assert.True(t, sessionExists(t, sessionsRepo, expired.UserUUID, expired.UUID))
	})
}
