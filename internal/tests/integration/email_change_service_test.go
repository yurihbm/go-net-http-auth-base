package integration_test

import (
	"context"
	"errors"
	"sync"
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

const (
	oldEmail = "old@example.com"
	newEmail = "new@example.com"
)

var emailChangeKey = []byte("email-change-transaction-key")

type emailChangeFixture struct {
	service           domain.EmailChangeService
	users             domain.UsersService
	emailChanges      domain.SessionChallengeRepository
	limiter           domain.EmailSendLimiter
	usersRepo         domain.UsersRepository
	sessionsRepo      domain.SessionsRepository
	authRepo          domain.AuthRepository
	emailVerification *mocks.EmailVerificationServiceMock
	user              *domain.User
	session           *domain.UserSession
}

func newEmailChangeFixture(t *testing.T, sessionsErr error, providersErr error) emailChangeFixture {
	t.Helper()
	ctx := context.Background()
	truncateTables(ctx, testDB)

	db := repositories.NewTxAwareDB(testDB)
	usersRepo := repositories.NewUsersPostgresRepository(db)
	sessionsRepo := repositories.NewSessionsPostgresRepository(db)
	authRepo := repositories.NewAuthPostgresRepository(db)
	emailChanges := repositories.NewSessionChallengesPostgresRepository(db)
	limiter := repositories.NewEmailSendLimitsPostgresRepository(db)
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

	return emailChangeFixture{
		service:           services.NewEmailChangeService(usersRepo, emailVerification, serviceSessionsRepo, serviceAuthRepo, emailChanges, limiter, repositories.NewPostgresTransactor(testDB), emailChangeKey),
		users:             services.NewUserService(usersRepo, repositories.NewPostgresTransactor(testDB)),
		emailChanges:      emailChanges,
		limiter:           limiter,
		usersRepo:         usersRepo,
		sessionsRepo:      sessionsRepo,
		authRepo:          authRepo,
		emailVerification: emailVerification,
		user:              user,
		session:           session,
	}
}

func emailChangeActor(f emailChangeFixture) domain.Actor {
	return domain.Actor{UUID: f.user.UUID, Role: domain.RoleUser}
}

func requestEmailChangeCode(t *testing.T, f emailChangeFixture) string {
	t.Helper()
	var code string
	f.emailVerification.On("SendEmailChangeCode", newEmail, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
		code = args.String(1)
	})
	require.NoError(t, f.service.RequestEmailChange(context.Background(), emailChangeActor(f), f.session.UUID, newEmail))
	return code
}

func applyEmailChange(t *testing.T, f emailChangeFixture) domain.UserOAuthProvider {
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

func TestEmailChangeService_ConfirmEmailChange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
	}

	t.Run("success", func(t *testing.T) {
		f := newEmailChangeFixture(t, nil, nil)
		code := requestEmailChangeCode(t, f)
		f.emailVerification.On("SendEmailChangedNotice", mock.Anything).Return(nil)

		_, err := f.service.ConfirmEmailChange(context.Background(), emailChangeActor(f), f.session.UUID, code)

		require.NoError(t, err)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, newEmail, stored.Email)
		assert.Equal(t, 1, stored.EmailVersion)
		assert.NotZero(t, stored.EmailChangedAt)
		assert.False(t, sessionExists(t, f.sessionsRepo, f.user.UUID, f.session.UUID))
		_, err = f.emailChanges.Attempt(context.Background(), f.user.UUID, f.session.UUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)
		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
	})

	t.Run("error - revoking sessions fails rolls back the email change", func(t *testing.T) {
		deleteErr := errors.New("delete failed")
		f := newEmailChangeFixture(t, deleteErr, nil)
		code := requestEmailChangeCode(t, f)

		_, err := f.service.ConfirmEmailChange(context.Background(), emailChangeActor(f), f.session.UUID, code)

		require.Error(t, err)
		assert.ErrorIs(t, err, deleteErr)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, oldEmail, stored.Email)
		assert.Equal(t, 0, stored.EmailVersion)
		assert.Zero(t, stored.EmailChangedAt)
		assert.True(t, sessionExists(t, f.sessionsRepo, f.user.UUID, f.session.UUID))
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
		challenge, err := f.emailChanges.Attempt(context.Background(), f.user.UUID, f.session.UUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)
		require.NoError(t, err)
		assert.Equal(t, newEmail, challenge.NewEmail)
	})

	t.Run("sign-up racing a confirm away from the email is rejected and the revert succeeds", func(t *testing.T) {
		f := newEmailChangeFixture(t, nil, nil)
		blocking := blockingDeleteAllSessionsRepository{SessionsRepository: f.sessionsRepo, reached: make(chan struct{}), release: make(chan struct{})}
		releaseOnce := sync.Once{}
		release := func() { releaseOnce.Do(func() { close(blocking.release) }) }
		t.Cleanup(release)
		service := services.NewEmailChangeService(f.usersRepo, f.emailVerification, blocking, f.authRepo, f.emailChanges, f.limiter, repositories.NewPostgresTransactor(testDB), emailChangeKey)
		code := requestEmailChangeCode(t, f)
		f.emailVerification.On("SendEmailChangedNotice", mock.Anything).Return(nil)

		confirmDone := make(chan error, 1)
		go func() {
			_, err := service.ConfirmEmailChange(context.Background(), emailChangeActor(f), f.session.UUID, code)
			confirmDone <- err
		}()
		<-blocking.reached

		signUpDone := make(chan error, 1)
		go func() {
			_, err := f.users.Create(context.Background(), domain.NewUserDTO{Name: "Squatter", Email: oldEmail, PasswordHash: "hash"})
			signUpDone <- err
		}()
		require.Eventually(t, func() bool {
			var waiting int
			require.NoError(t, testDB.QueryRow(context.Background(),
				"SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE '%INSERT INTO users%'").Scan(&waiting))
			return waiting > 0
		}, 10*time.Second, 10*time.Millisecond)
		release()

		require.NoError(t, <-confirmDone)
		var conflictErr *domain.ConflictError
		require.True(t, errors.As(<-signUpDone, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())

		f.emailVerification.On("VerifyEmailChangeRevertToken", "revert-token").Return(&domain.EmailChangeRevert{
			UserUUID:  f.user.UUID,
			OldEmail:  oldEmail,
			NewEmail:  newEmail,
			Version:   1,
			ChangedAt: time.Now().Unix(),
		}, nil)
		revertService := services.NewEmailChangeService(f.usersRepo, f.emailVerification, f.sessionsRepo, f.authRepo, f.emailChanges, f.limiter, repositories.NewPostgresTransactor(testDB), emailChangeKey)
		_, err := revertService.RevertEmailChange(context.Background(), "revert-token")
		require.NoError(t, err)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, oldEmail, stored.Email)
	})
}

func TestEmailChangeService_RevertEmailChange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
	}

	t.Run("success", func(t *testing.T) {
		f := newEmailChangeFixture(t, nil, nil)
		provider := applyEmailChange(t, f)

		_, err := f.service.RevertEmailChange(context.Background(), "token")

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

	t.Run("error - removing linked providers fails rolls back everything", func(t *testing.T) {
		deleteErr := errors.New("delete failed")
		f := newEmailChangeFixture(t, nil, deleteErr)
		applyEmailChange(t, f)

		_, err := f.service.RevertEmailChange(context.Background(), "token")

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

	t.Run("success after a squatting sign-up on the previous email was rejected", func(t *testing.T) {
		f := newEmailChangeFixture(t, nil, nil)
		applyEmailChange(t, f)

		_, err := f.users.Create(context.Background(), domain.NewUserDTO{Name: "Squatter", Email: oldEmail, PasswordHash: "hash"})

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())

		_, err = f.service.RevertEmailChange(context.Background(), "token")
		require.NoError(t, err)
		stored, err := f.usersRepo.FindByUUID(context.Background(), f.user.UUID)
		require.NoError(t, err)
		assert.Equal(t, oldEmail, stored.Email)
	})
}
