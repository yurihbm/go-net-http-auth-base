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

type failingDeleteAllSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingDeleteAllSessionsRepository) DeleteAllByUser(context.Context, string) error {
	return r.err
}

type failingDeleteProvidersAuthRepository struct {
	domain.AuthRepository
	err error
}

func (r failingDeleteProvidersAuthRepository) DeleteOAuthProvidersCreatedSince(context.Context, string, time.Time) error {
	return r.err
}

func TestEmailChange_Transaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const (
		oldEmail = "old@example.com"
		newEmail = "new@example.com"
	)

	type fixture struct {
		service           domain.UsersService
		usersRepo         domain.UsersRepository
		sessionsRepo      domain.SessionsRepository
		authRepo          domain.AuthRepository
		emailVerification *mocks.EmailVerificationServiceMock
		user              *domain.User
		session           *domain.UserSession
	}

	setup := func(t *testing.T, sessionsErr error, providersErr error) fixture {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)
		authRepo := repositories.NewAuthPostgresRepository(db)
		emailVerification := new(mocks.EmailVerificationServiceMock)

		user, err := usersRepo.Create(ctx, domain.User{Name: "Change User", Email: oldEmail, Role: domain.RoleUser})
		require.NoError(t, err)
		session := seedSession(t, sessionsRepo, user.UUID, "jti")

		serviceSessionsRepo := sessionsRepo
		if sessionsErr != nil {
			serviceSessionsRepo = failingDeleteAllSessionsRepository{SessionsRepository: sessionsRepo, err: sessionsErr}
		}
		serviceAuthRepo := authRepo
		if providersErr != nil {
			serviceAuthRepo = failingDeleteProvidersAuthRepository{AuthRepository: authRepo, err: providersErr}
		}

		return fixture{
			service:           services.NewUserService(usersRepo, emailVerification, serviceSessionsRepo, serviceAuthRepo, repositories.NewPostgresTransactor(testDB)),
			usersRepo:         usersRepo,
			sessionsRepo:      sessionsRepo,
			authRepo:          authRepo,
			emailVerification: emailVerification,
			user:              user,
			session:           session,
		}
	}

	t.Run("confirm - success", func(t *testing.T) {
		f := setup(t, nil, nil)
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(&domain.EmailChange{UserUUID: f.user.UUID, CurrentEmail: oldEmail, NewEmail: newEmail, Version: 0}, nil)
		f.emailVerification.On("SendEmailChangedNotice", mock.Anything).Return(nil)

		_, err := f.service.ConfirmEmailChange(context.Background(), "token")

		require.NoError(t, err)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, newEmail, stored.Email)
		assert.Equal(t, 1, stored.EmailVersion)
		assert.NotZero(t, stored.EmailChangedAt)
		assert.False(t, sessionExists(t, f.sessionsRepo, f.user.UUID, f.session.UUID))
	})

	t.Run("confirm - error - revoking sessions fails rolls back the email change", func(t *testing.T) {
		deleteErr := errors.New("delete failed")
		f := setup(t, deleteErr, nil)
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(&domain.EmailChange{UserUUID: f.user.UUID, CurrentEmail: oldEmail, NewEmail: newEmail, Version: 0}, nil)

		_, err := f.service.ConfirmEmailChange(context.Background(), "token")

		require.Error(t, err)
		assert.ErrorIs(t, err, deleteErr)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, oldEmail, stored.Email)
		assert.Equal(t, 0, stored.EmailVersion)
		assert.Zero(t, stored.EmailChangedAt)
		assert.True(t, sessionExists(t, f.sessionsRepo, f.user.UUID, f.session.UUID))
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
	})

	applyChange := func(t *testing.T, f fixture) domain.UserOAuthProvider {
		t.Helper()
		changedAt := time.Now().Add(-time.Hour)
		_, err := f.usersRepo.UpdateEmail(context.Background(), f.user.UUID, newEmail, 0, &changedAt)
		require.NoError(t, err)
		provider, err := f.authRepo.CreateUserOAuthProvider(context.Background(), domain.UserOAuthProvider{
			UserUUID:       f.user.UUID,
			Provider:       domain.OAuthProviderGoogle,
			ProviderUserID: "attacker-google-id",
			ProviderEmail:  newEmail,
		})
		require.NoError(t, err)
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(&domain.EmailChangeRevert{
			UserUUID:  f.user.UUID,
			OldEmail:  oldEmail,
			NewEmail:  newEmail,
			Version:   1,
			ChangedAt: changedAt.Unix(),
		}, nil)
		return *provider
	}

	t.Run("revert - success", func(t *testing.T) {
		f := setup(t, nil, nil)
		provider := applyChange(t, f)

		err := f.service.RevertEmailChange(context.Background(), "token")

		require.NoError(t, err)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, oldEmail, stored.Email)
		assert.Equal(t, 2, stored.EmailVersion)
		assert.Zero(t, stored.EmailChangedAt)
		assert.False(t, sessionExists(t, f.sessionsRepo, f.user.UUID, f.session.UUID))
		providers, err := f.authRepo.ListUserOAuthProvidersByUserUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.NotContains(t, providers, provider)
	})

	t.Run("revert - error - removing linked providers fails rolls back everything", func(t *testing.T) {
		deleteErr := errors.New("delete failed")
		f := setup(t, nil, deleteErr)
		applyChange(t, f)

		err := f.service.RevertEmailChange(context.Background(), "token")

		require.Error(t, err)
		assert.ErrorIs(t, err, deleteErr)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, newEmail, stored.Email)
		assert.Equal(t, 1, stored.EmailVersion)
		assert.NotZero(t, stored.EmailChangedAt)
		assert.True(t, sessionExists(t, f.sessionsRepo, f.user.UUID, f.session.UUID))
		providers, err := f.authRepo.ListUserOAuthProvidersByUserUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Len(t, providers, 1)
	})

	t.Run("revert - success after a squatting sign-up on the previous email was rejected", func(t *testing.T) {
		f := setup(t, nil, nil)
		applyChange(t, f)

		_, err := f.service.Create(context.Background(), domain.CreateUserDTO{Name: "Squatter", Email: oldEmail, Password: "password123"})

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())

		require.NoError(t, f.service.RevertEmailChange(context.Background(), "token"))
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, oldEmail, stored.Email)
	})
}
