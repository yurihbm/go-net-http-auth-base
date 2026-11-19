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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCompleteSignup_Transaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const email = "signup@example.com"

	type fixture struct {
		service     domain.AuthService
		usersRepo   domain.UsersRepository
		pendingRepo domain.PendingSignupRepository
		pendingUUID string
		code        string
	}

	setup := func(t *testing.T, trimErr error) fixture {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		transactor := repositories.NewPostgresTransactor(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		pendingRepo := repositories.NewPendingSignupsPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)
		if trimErr != nil {
			sessionsRepo = failingTrimSessionsRepository{SessionsRepository: sessionsRepo, err: trimErr}
		}

		emails := new(mocks.EmailVerificationServiceMock)
		var code string
		emails.On("SendSignupCode", email, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
			code = args.String(1)
		})
		pendingSignups := services.NewPendingSignupService(
			pendingRepo,
			repositories.NewEmailSendLimitsPostgresRepository(db),
			usersRepo,
			transactor,
			emails,
			[]byte("test-secret-key"),
		)
		service := services.NewAuthService(
			services.NewUserService(usersRepo, emails, nil, nil, nil, nil, transactor, nil),
			pendingSignups,
			repositories.NewAuthPostgresRepository(db),
			sessionsRepo,
			new(mocks.OAuthProviderRegistryMock),
			transactor,
			services.NewTokenService("test-secret-key"),
			30*24*time.Hour,
			10,
		)

		pendingUUID, err := pendingSignups.StartCredentials(ctx, domain.CreateUserDTO{Name: "Signup User", Email: email, Password: "password123"})
		require.NoError(t, err)
		require.NotEmpty(t, code)

		return fixture{service: service, usersRepo: usersRepo, pendingRepo: pendingRepo, pendingUUID: pendingUUID, code: code}
	}

	countUsers := func(t *testing.T) int {
		t.Helper()
		var count int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&count))
		return count
	}

	t.Run("success creates the user and consumes the pending signup", func(t *testing.T) {
		f := setup(t, nil)

		result, err := f.service.CompleteSignup(context.Background(), f.pendingUUID, f.code)

		require.NoError(t, err)
		assert.Equal(t, email, result.User.Email)
		assert.NotEmpty(t, result.Tokens.AccessToken)
		stored, err := f.usersRepo.FindByEmail(context.Background(), email)
		require.NoError(t, err)
		assert.NotEmpty(t, stored.PasswordHash)
		_, err = f.pendingRepo.FindByUUID(context.Background(), f.pendingUUID)
		assert.ErrorIs(t, err, domain.ErrSignupNoPending)
	})

	t.Run("error - session start fails rolls back the user and keeps the pending signup", func(t *testing.T) {
		trimErr := errors.New("trim failed")
		f := setup(t, trimErr)

		result, err := f.service.CompleteSignup(context.Background(), f.pendingUUID, f.code)

		require.Error(t, err)
		assert.ErrorIs(t, err, trimErr)
		assert.Nil(t, result)
		assert.Equal(t, 0, countUsers(t))
		assert.Equal(t, 1, pendingSignupAttempts(t, f.pendingUUID))
	})

	t.Run("error - email taken meanwhile keeps the pending signup", func(t *testing.T) {
		f := setup(t, nil)
		_, err := f.usersRepo.Create(context.Background(), domain.User{Name: "Other", Email: email, PasswordHash: "hash", Role: domain.RoleUser})
		require.NoError(t, err)

		_, err = f.service.CompleteSignup(context.Background(), f.pendingUUID, f.code)

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, 1, countUsers(t))
		_, err = f.pendingRepo.FindByUUID(context.Background(), f.pendingUUID)
		assert.NoError(t, err)
	})

	t.Run("error - wrong code is counted although nothing else is written", func(t *testing.T) {
		f := setup(t, nil)
		wrong := "000000"
		if f.code == wrong {
			wrong = "111111"
		}

		_, err := f.service.CompleteSignup(context.Background(), f.pendingUUID, wrong)

		assert.ErrorIs(t, err, domain.ErrSignupInvalidCode)
		assert.Equal(t, 1, pendingSignupAttempts(t, f.pendingUUID))
		var failures int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT failures FROM email_send_limits WHERE email = $1", email).Scan(&failures))
		assert.Equal(t, 1, failures)
		assert.Equal(t, 0, countUsers(t))
	})
}
