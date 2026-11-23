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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPasswordService_ResetPassword_Transaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const email = "reset@example.com"

	type fixture struct {
		service   domain.PasswordService
		usersRepo domain.UsersRepository
		user      *domain.User
		sessions  domain.SessionsRepository
		resetUUID string
		code      string
	}

	setup := func(t *testing.T, deleteAllErr error) fixture {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)
		serviceSessions := domain.SessionsRepository(sessionsRepo)
		if deleteAllErr != nil {
			serviceSessions = failingDeleteAllSessionsRepository{SessionsRepository: sessionsRepo, err: deleteAllErr}
		}

		emails := new(mocks.EmailVerificationServiceMock)
		var code string
		emails.On("SendPasswordResetCode", email, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
			code = args.String(1)
		})
		emails.On("SendPasswordChangedNotice", email).Return(nil)
		service := services.NewPasswordService(
			repositories.NewPasswordResetsPostgresRepository(db),
			usersRepo,
			serviceSessions,
			repositories.NewEmailSendLimitsPostgresRepository(db),
			repositories.NewPostgresTransactor(testDB),
			emails,
			[]byte("test-secret-key"),
		)

		user, err := usersRepo.Create(ctx, domain.User{Name: "Reset User", Email: email, PasswordHash: "old-hash", Role: domain.RoleUser})
		require.NoError(t, err)
		_, err = sessionsRepo.Create(ctx, domain.UserSession{
			UserUUID:   user.UUID,
			CurrentJTI: uuid.Must(uuid.NewV7()).String(),
			ExpiresAt:  time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)

		resetUUID, err := service.RequestReset(ctx, email)
		require.NoError(t, err)
		require.NotEmpty(t, code)

		return fixture{service: service, usersRepo: usersRepo, user: user, sessions: sessionsRepo, resetUUID: resetUUID, code: code}
	}

	countSessions := func(t *testing.T) int {
		t.Helper()
		var count int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM user_sessions").Scan(&count))
		return count
	}

	t.Run("success updates the password, revokes sessions and consumes the reset", func(t *testing.T) {
		f := setup(t, nil)

		user, err := f.service.ResetPassword(context.Background(), f.resetUUID, domain.ResetPasswordDTO{Code: f.code, Password: "new-password-1"})

		require.NoError(t, err)
		assert.Equal(t, f.user.UUID, user.UUID)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.NotEqual(t, "old-hash", stored.PasswordHash)
		assert.Equal(t, 0, countSessions(t))
		assert.Equal(t, 0, countPasswordResets(t))
	})

	t.Run("error - session revocation fails rolls back the password and keeps the reset", func(t *testing.T) {
		deleteErr := errors.New("delete failed")
		f := setup(t, deleteErr)

		user, err := f.service.ResetPassword(context.Background(), f.resetUUID, domain.ResetPasswordDTO{Code: f.code, Password: "new-password-1"})

		require.Error(t, err)
		assert.ErrorIs(t, err, deleteErr)
		assert.Nil(t, user)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, "old-hash", stored.PasswordHash)
		assert.Equal(t, 1, countSessions(t))
		assert.Equal(t, 1, countPasswordResets(t))
		assert.Equal(t, 1, passwordResetAttempts(t, f.resetUUID))
	})

	t.Run("error - email changed meanwhile keeps the old password", func(t *testing.T) {
		f := setup(t, nil)
		changedAt := time.Now()
		_, err := f.usersRepo.UpdateEmail(context.Background(), f.user.UUID, "moved@example.com", f.user.EmailVersion, &changedAt)
		require.NoError(t, err)

		_, err = f.service.ResetPassword(context.Background(), f.resetUUID, domain.ResetPasswordDTO{Code: f.code, Password: "new-password-1"})

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, "old-hash", stored.PasswordHash)
		assert.Equal(t, 1, countPasswordResets(t))
	})

	t.Run("error - wrong code is counted although nothing else is written", func(t *testing.T) {
		f := setup(t, nil)
		wrong := "000000"
		if f.code == wrong {
			wrong = "111111"
		}

		_, err := f.service.ResetPassword(context.Background(), f.resetUUID, domain.ResetPasswordDTO{Code: wrong, Password: "new-password-1"})

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		assert.Equal(t, 1, passwordResetAttempts(t, f.resetUUID))
		var failures int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT failures FROM email_send_limits WHERE email = $1", email).Scan(&failures))
		assert.Equal(t, 1, failures)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, "old-hash", stored.PasswordHash)
	})
}
