package repositories_test

import (
	"context"
	"sync"
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

func TestRefreshTokenRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	const (
		email    = "rotation@example.com"
		password = "password123"
	)
	ctx := context.Background()

	type fixture struct {
		service      domain.AuthService
		usersRepo    domain.UsersRepository
		sessionsRepo domain.SessionsRepository
		user         *domain.User
	}

	setup := func(t *testing.T, sessionMaxAge time.Duration, maxSessions int) fixture {
		t.Helper()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		require.NoError(t, err)
		user, err := usersRepo.Create(ctx, domain.User{Name: "Rotation", Email: email, PasswordHash: string(hash)})
		require.NoError(t, err)

		service := services.NewAuthService(
			services.NewUserService(usersRepo, new(mocks.EmailVerificationServiceMock)),
			repositories.NewAuthPostgresRepository(db),
			sessionsRepo,
			new(mocks.OAuthProviderRegistryMock),
			repositories.NewPostgresTransactor(testDB),
			services.NewTokenService("test-secret-key"),
			sessionMaxAge,
			maxSessions,
		)
		return fixture{service, usersRepo, sessionsRepo, user}
	}

	login := func(t *testing.T, f fixture) domain.AuthTokens {
		t.Helper()
		tokens, err := f.service.CredentialsLogin(ctx, domain.CredentialsLoginDTO{Email: email, Password: password})
		require.NoError(t, err)
		return tokens
	}

	refresh := func(f fixture, tokens domain.AuthTokens) (domain.AuthTokens, error) {
		return f.service.RefreshToken(ctx, domain.RefreshTokenDTO{RefreshToken: tokens.RefreshToken})
	}

	sessionID := func(t *testing.T, f fixture, tokens domain.AuthTokens) string {
		t.Helper()
		data, err := f.service.VerifyToken(ctx, domain.VerifyTokenDTO{Token: tokens.RefreshToken, Audience: domain.TokenAudienceRefresh})
		require.NoError(t, err)
		return data.SessionID
	}

	sessionExists := func(t *testing.T, f fixture, sid string) bool {
		t.Helper()
		_, err := f.sessionsRepo.FindByUUID(ctx, f.user.UUID, sid)
		return err == nil
	}

	t.Run("refresh keeps the session and rotates the token", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		original := login(t, f)

		rotated, err := refresh(f, original)

		require.NoError(t, err)
		assert.Equal(t, sessionID(t, f, original), sessionID(t, f, rotated))
		assert.NotEqual(t, original.RefreshToken, rotated.RefreshToken)
		_, err = refresh(f, rotated)
		assert.NoError(t, err)
	})

	t.Run("reusing a rotated token revokes that session", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		original := login(t, f)
		rotated, err := refresh(f, original)
		require.NoError(t, err)

		_, err = refresh(f, original)
		assert.ErrorIs(t, err, services.ErrInvalidToken)

		_, err = refresh(f, rotated)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.False(t, sessionExists(t, f, sessionID(t, f, original)))
	})

	t.Run("concurrent refreshes with the same token have a single winner and revoke the session", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		tokens := login(t, f)

		const attempts = 10
		results := make([]domain.AuthTokens, attempts)
		errs := make([]error, attempts)
		var wg sync.WaitGroup
		for i := range attempts {
			wg.Go(func() {
				results[i], errs[i] = refresh(f, tokens)
			})
		}
		wg.Wait()

		succeeded := 0
		var winner domain.AuthTokens
		for i, err := range errs {
			if err == nil {
				succeeded++
				winner = results[i]
				continue
			}
			assert.ErrorIs(t, err, services.ErrInvalidToken)
		}
		require.Equal(t, 1, succeeded)
		_, err := refresh(f, winner)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.False(t, sessionExists(t, f, sessionID(t, f, tokens)))
	})

	t.Run("sessions from different logins are independent", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		web := login(t, f)
		mobile := login(t, f)
		require.NotEqual(t, sessionID(t, f, web), sessionID(t, f, mobile))

		web, err := refresh(f, web)
		require.NoError(t, err)
		mobile, err = refresh(f, mobile)
		require.NoError(t, err)

		require.NoError(t, f.service.Logout(ctx, f.user.UUID, sessionID(t, f, web)))

		_, err = refresh(f, web)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
		_, err = refresh(f, mobile)
		assert.NoError(t, err)
	})

	t.Run("logout is idempotent", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		tokens := login(t, f)
		sid := sessionID(t, f, tokens)

		require.NoError(t, f.service.Logout(ctx, f.user.UUID, sid))
		assert.NoError(t, f.service.Logout(ctx, f.user.UUID, sid))
	})

	t.Run("the cap evicts the least recently used session", func(t *testing.T) {
		f := setup(t, time.Hour, 2)
		first := login(t, f)
		second := login(t, f)
		first, err := refresh(f, first)
		require.NoError(t, err)

		third := login(t, f)

		_, err = refresh(f, second)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
		_, err = refresh(f, first)
		assert.NoError(t, err)
		_, err = refresh(f, third)
		assert.NoError(t, err)
	})

	t.Run("login removes the user's expired sessions", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		stale := login(t, f)
		_, err := testDB.Exec(ctx, "UPDATE user_sessions SET expires_at = now() - interval '1 minute' WHERE uuid = $1", sessionID(t, f, stale))
		require.NoError(t, err)

		login(t, f)

		assert.False(t, sessionExists(t, f, sessionID(t, f, stale)))
	})

	t.Run("refresh fails and deletes the session once it exceeds the max age", func(t *testing.T) {
		f := setup(t, time.Nanosecond, 10)
		tokens := login(t, f)

		_, err := refresh(f, tokens)

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.False(t, sessionExists(t, f, sessionID(t, f, tokens)))
	})

	t.Run("refresh fails for a deleted user", func(t *testing.T) {
		f := setup(t, time.Hour, 10)
		tokens := login(t, f)
		require.NoError(t, f.usersRepo.Delete(ctx, f.user.UUID))

		_, err := refresh(f, tokens)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
	})
}
