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

type failingDeleteOthersSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingDeleteOthersSessionsRepository) DeleteOthersByUser(context.Context, string, string) error {
	return r.err
}

func TestPasswordChange_Transaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const email = "change@example.com"

	type fixture struct {
		service        domain.PasswordService
		usersRepo      domain.UsersRepository
		user           *domain.User
		currentSession string
	}

	setup := func(t *testing.T, deleteOthersErr error) fixture {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)
		serviceSessions := domain.SessionsRepository(sessionsRepo)
		if deleteOthersErr != nil {
			serviceSessions = failingDeleteOthersSessionsRepository{SessionsRepository: sessionsRepo, err: deleteOthersErr}
		}

		emails := new(mocks.EmailVerificationServiceMock)
		emails.On("SendPasswordResetCode", email, mock.Anything).Return(nil)
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

		user, err := usersRepo.Create(ctx, domain.User{Name: "Change User", Email: email, PasswordHash: "old-hash", Role: domain.RoleUser})
		require.NoError(t, err)
		var current string
		for range 2 {
			session, err := sessionsRepo.Create(ctx, domain.UserSession{
				UserUUID:   user.UUID,
				CurrentJTI: uuid.Must(uuid.NewV7()).String(),
				ExpiresAt:  time.Now().Add(time.Hour).Unix(),
			})
			require.NoError(t, err)
			current = session.UUID
		}

		_, err = service.RequestReset(ctx, email)
		require.NoError(t, err)

		return fixture{service: service, usersRepo: usersRepo, user: user, currentSession: current}
	}

	sessionUUIDs := func(t *testing.T) []string {
		t.Helper()
		rows, err := testDB.Query(context.Background(), "SELECT uuid::text FROM user_sessions")
		require.NoError(t, err)
		defer rows.Close()
		var uuids []string
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			uuids = append(uuids, id)
		}
		require.NoError(t, rows.Err())
		return uuids
	}

	t.Run("success updates the password, keeps only the current session and deletes resets", func(t *testing.T) {
		f := setup(t, nil)

		err := f.service.ChangePassword(context.Background(), domain.Actor{UUID: f.user.UUID}, f.currentSession, domain.ChangePasswordDTO{NewPassword: "new-password-1"})

		require.NoError(t, err)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.NotEqual(t, "old-hash", stored.PasswordHash)
		assert.Equal(t, []string{f.currentSession}, sessionUUIDs(t))
		assert.Equal(t, 0, countPasswordResets(t))
	})

	t.Run("error - session revocation fails rolls back the password and keeps the resets", func(t *testing.T) {
		deleteErr := errors.New("delete failed")
		f := setup(t, deleteErr)

		err := f.service.ChangePassword(context.Background(), domain.Actor{UUID: f.user.UUID}, f.currentSession, domain.ChangePasswordDTO{NewPassword: "new-password-1"})

		require.Error(t, err)
		assert.ErrorIs(t, err, deleteErr)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, "old-hash", stored.PasswordHash)
		assert.Len(t, sessionUUIDs(t), 2)
		assert.Equal(t, 1, countPasswordResets(t))
	})
}
