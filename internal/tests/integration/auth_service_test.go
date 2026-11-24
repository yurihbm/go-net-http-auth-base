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
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_CredentialsLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
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
			services.NewUserService(usersRepo, repositories.NewPostgresTransactor(testDB), time.Now),
			nil,
			repositories.NewAuthPostgresRepository(db),
			serviceSessionsRepo,
			new(mocks.OAuthProviderRegistryMock),
			repositories.NewPostgresTransactor(testDB),
			services.NewTokenService("test-secret-key", time.Now),
			nil,
			30*24*time.Hour,
			10,
			time.Now,
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

func TestAuthService_OAuthLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
	}

	const (
		provider       = domain.OAuthProviderGoogle
		providerUserID = "google-user-123"
		code           = "auth-code"
		providerEmail  = "  New-OAuth@Example.COM "
		email          = "new-oauth@example.com"
		nonce          = "browser-nonce"
		codeVerifier   = "code-verifier"
	)

	var emails *mocks.EmailVerificationServiceMock
	setup := func(t *testing.T, linkErr error) (domain.AuthService, domain.UsersRepository, domain.AuthRepository, string) {
		t.Helper()
		truncateTables(context.Background(), testDB)
		emails = new(mocks.EmailVerificationServiceMock)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		authRepo := repositories.NewAuthPostgresRepository(db)

		serviceAuthRepo := authRepo
		if linkErr != nil {
			serviceAuthRepo = failingLinkAuthRepository{AuthRepository: authRepo, err: linkErr}
		}

		providerMock := new(mocks.OAuthProviderMock)
		providerMock.On("GetUserInfo", mock.Anything, code, codeVerifier).Return(&domain.OAuthProviderUserInfo{
			ID:            providerUserID,
			Name:          "New OAuth User",
			Email:         providerEmail,
			EmailVerified: true,
		}, nil)
		registry := new(mocks.OAuthProviderRegistryMock)
		registry.On("Get", provider).Return(providerMock, nil)

		service := services.NewAuthService(
			services.NewUserService(usersRepo, repositories.NewPostgresTransactor(testDB), time.Now),
			nil,
			serviceAuthRepo,
			repositories.NewSessionsPostgresRepository(db),
			registry,
			repositories.NewPostgresTransactor(testDB),
			services.NewTokenService("test-secret-key", time.Now),
			emails,
			30*24*time.Hour,
			10,
			time.Now,
		)

		state, err := service.(domain.TokenGenerator).GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  string(provider),
			Audience: domain.TokenAudienceOAuthState,
			Payload:  map[string]string{"redirect_uri": "http://localhost:3000/callback", "nonce": nonce},
		})
		require.NoError(t, err)

		return service, usersRepo, authRepo, state
	}

	t.Run("creates the user and links the provider", func(t *testing.T) {
		service, usersRepo, authRepo, state := setup(t, nil)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		created, err := usersRepo.FindByEmail(context.Background(), email)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, result.User.UUID)
		linked, err := authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, linked.UserUUID)
		assert.Equal(t, email, linked.ProviderEmail)
	})

	t.Run("concurrent callbacks resolve to a single user", func(t *testing.T) {
		service, _, _, state := setup(t, nil)

		const callbacks = 5
		results := make([]*domain.OAuthLoginResult, callbacks)
		errs := make([]error, callbacks)
		var wg sync.WaitGroup
		for i := range callbacks {
			wg.Go(func() {
				results[i], errs[i] = service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})
			})
		}
		wg.Wait()

		for i := range callbacks {
			require.NoError(t, errs[i])
			assert.Equal(t, results[0].User.UUID, results[i].User.UUID)
		}
		var users, links int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&users))
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM user_oauth_providers").Scan(&links))
		assert.Equal(t, 1, users)
		assert.Equal(t, 1, links)
		emails.AssertNotCalled(t, "SendOAuthLinkedNotice", mock.Anything, mock.Anything)
	})

	t.Run("links an existing local account", func(t *testing.T) {
		service, usersRepo, authRepo, state := setup(t, nil)
		existing, err := usersRepo.Create(context.Background(), domain.User{Name: "Local", Email: email, Role: domain.RoleUser})
		require.NoError(t, err)
		var notice domain.OAuthLinkRevert
		emails.On("SendOAuthLinkedNotice", email, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			notice = args.Get(1).(domain.OAuthLinkRevert)
			var committed int
			require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM user_oauth_providers WHERE uuid = $1", notice.LinkUUID).Scan(&committed))
			assert.Equal(t, 1, committed, "notice sent before the link was committed")
		})

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		require.NoError(t, err)
		assert.Equal(t, existing.UUID, result.User.UUID)
		linked, err := authRepo.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), provider, providerUserID)
		require.NoError(t, err)
		assert.Equal(t, existing.UUID, linked.UserUUID)
		assert.Equal(t, domain.OAuthLinkRevert{UserUUID: existing.UUID, LinkUUID: linked.UUID, Provider: provider}, notice)
		emails.AssertExpectations(t)
	})

	t.Run("leaves no orphaned user when linking fails", func(t *testing.T) {
		linkErr := errors.New("link failed")
		service, usersRepo, _, state := setup(t, linkErr)

		result, err := service.OAuthLogin(context.Background(), domain.OAuthLoginDTO{Provider: provider, State: state, Code: code, Nonce: nonce, CodeVerifier: codeVerifier})

		assert.Equal(t, linkErr, err)
		assert.Nil(t, result)
		_, err = usersRepo.FindByEmail(context.Background(), email)
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})
}

func TestAuthService_CompleteSignup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
	}

	t.Run("credentials", completeSignupCredentialsTests)
	t.Run("oauth", completeSignupOAuthTests)
}

func completeSignupCredentialsTests(t *testing.T) {

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
			time.Now,
		)
		service := services.NewAuthService(
			services.NewUserService(usersRepo, transactor, time.Now),
			pendingSignups,
			repositories.NewAuthPostgresRepository(db),
			sessionsRepo,
			new(mocks.OAuthProviderRegistryMock),
			transactor,
			services.NewTokenService("test-secret-key", time.Now),
			nil,
			30*24*time.Hour,
			10,
			time.Now,
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

func completeSignupOAuthTests(t *testing.T) {

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
			time.Now,
		)
		service := services.NewAuthService(
			services.NewUserService(usersRepo, transactor, time.Now),
			pendingSignups,
			serviceAuthRepo,
			repositories.NewSessionsPostgresRepository(db),
			new(mocks.OAuthProviderRegistryMock),
			transactor,
			services.NewTokenService("test-secret-key", time.Now),
			nil,
			30*24*time.Hour,
			10,
			time.Now,
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
