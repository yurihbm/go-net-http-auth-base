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

func TestCompleteSignup_OAuthTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const (
		provider       = domain.OAuthProviderGitHub
		providerUserID = "gh-user-1"
		email          = "oauth-signup@example.com"
	)

	type fixture struct {
		service     domain.AuthService
		usersRepo   domain.UsersRepository
		authRepo    domain.AuthRepository
		pendingRepo domain.PendingSignupRepository
		pendingUUID string
		code        string
	}

	setup := func(t *testing.T, linkErr error) fixture {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		transactor := repositories.NewPostgresTransactor(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		authRepo := repositories.NewAuthPostgresRepository(db)
		pendingRepo := repositories.NewPendingSignupsPostgresRepository(db)

		serviceAuthRepo := authRepo
		if linkErr != nil {
			serviceAuthRepo = failingLinkAuthRepository{AuthRepository: authRepo, err: linkErr}
		}

		emails := new(mocks.EmailVerificationServiceMock)
		var code string
		emails.On("SendOAuthSignupCode", email, mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
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
			services.NewUserService(usersRepo, transactor),
			pendingSignups,
			serviceAuthRepo,
			repositories.NewSessionsPostgresRepository(db),
			new(mocks.OAuthProviderRegistryMock),
			transactor,
			services.NewTokenService("test-secret-key"),
			nil,
			30*24*time.Hour,
			10,
		)

		pendingUUID, err := pendingSignups.StartOAuth(ctx, domain.StartOAuthSignupDTO{Name: "OAuth User", Email: email, Provider: provider, ProviderUserID: providerUserID})
		require.NoError(t, err)
		require.NotEmpty(t, code)

		return fixture{service: service, usersRepo: usersRepo, authRepo: authRepo, pendingRepo: pendingRepo, pendingUUID: pendingUUID, code: code}
	}

	t.Run("creates the user, links the provider and consumes the pending signup", func(t *testing.T) {
		f := setup(t, nil)

		result, err := f.service.CompleteSignup(context.Background(), f.pendingUUID, f.code)

		require.NoError(t, err)
		assert.Equal(t, email, result.User.Email)
		assert.NotEmpty(t, result.Tokens.AccessToken)
		linked, err := f.authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		require.NoError(t, err)
		assert.Equal(t, result.User.UUID, linked.UserUUID)
		_, err = f.pendingRepo.FindByUUID(context.Background(), f.pendingUUID)
		assert.ErrorIs(t, err, domain.ErrSignupNoPending)
	})

	t.Run("links into the existing account that owns the email", func(t *testing.T) {
		f := setup(t, nil)
		existing, err := f.usersRepo.Create(context.Background(), domain.User{Name: "Local", Email: email, PasswordHash: "hash", Role: domain.RoleUser})
		require.NoError(t, err)

		result, err := f.service.CompleteSignup(context.Background(), f.pendingUUID, f.code)

		require.NoError(t, err)
		assert.Equal(t, existing.UUID, result.User.UUID)
		linked, err := f.authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		require.NoError(t, err)
		assert.Equal(t, existing.UUID, linked.UserUUID)
	})

	t.Run("leaves no user and keeps the pending signup when linking fails", func(t *testing.T) {
		linkErr := errors.New("link failed")
		f := setup(t, linkErr)

		result, err := f.service.CompleteSignup(context.Background(), f.pendingUUID, f.code)

		assert.Equal(t, linkErr, err)
		assert.Nil(t, result)
		_, err = f.usersRepo.FindByEmail(context.Background(), email)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
		_, err = f.pendingRepo.FindByUUID(context.Background(), f.pendingUUID)
		assert.NoError(t, err)
	})
}
