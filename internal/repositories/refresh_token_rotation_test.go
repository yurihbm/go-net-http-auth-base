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

	setup := func(t *testing.T, sessionMaxAge time.Duration) (domain.AuthService, domain.UsersRepository, *domain.User) {
		t.Helper()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		require.NoError(t, err)
		user, err := usersRepo.Create(ctx, domain.User{Name: "Rotation", Email: email, PasswordHash: string(hash)})
		require.NoError(t, err)

		service := services.NewAuthService(
			services.NewUserService(usersRepo, new(mocks.EmailVerificationServiceMock)),
			repositories.NewAuthPostgresRepository(db),
			new(mocks.OAuthProviderRegistryMock),
			repositories.NewPostgresTransactor(testDB),
			services.NewTokenService("test-secret-key"),
			sessionMaxAge,
		)
		return service, usersRepo, user
	}

	login := func(t *testing.T, service domain.AuthService) domain.AuthTokens {
		t.Helper()
		tokens, err := service.CredentialsLogin(ctx, domain.CredentialsLoginDTO{Email: email, Password: password})
		require.NoError(t, err)
		return tokens
	}

	refresh := func(service domain.AuthService, tokens domain.AuthTokens) (domain.AuthTokens, error) {
		return service.RefreshToken(ctx, domain.RefreshTokenDTO{RefreshToken: tokens.RefreshToken})
	}

	t.Run("rotated refresh token cannot be reused", func(t *testing.T) {
		service, _, _ := setup(t, time.Hour)
		original := login(t, service)

		rotated, err := refresh(service, original)
		require.NoError(t, err)

		_, err = refresh(service, original)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
		_, err = refresh(service, rotated)
		assert.NoError(t, err)
	})

	t.Run("concurrent refreshes with the same token have a single winner", func(t *testing.T) {
		service, _, _ := setup(t, time.Hour)
		tokens := login(t, service)

		const attempts = 10
		errs := make([]error, attempts)
		var wg sync.WaitGroup
		for i := range attempts {
			wg.Go(func() {
				_, errs[i] = refresh(service, tokens)
			})
		}
		wg.Wait()

		succeeded := 0
		for _, err := range errs {
			if err == nil {
				succeeded++
				continue
			}
			assert.ErrorIs(t, err, services.ErrInvalidToken)
		}
		assert.Equal(t, 1, succeeded)
	})

	t.Run("logout invalidates the refresh token", func(t *testing.T) {
		service, _, _ := setup(t, time.Hour)
		tokens := login(t, service)

		require.NoError(t, service.Logout(ctx, domain.LogoutDTO{AccessToken: tokens.AccessToken}))

		_, err := refresh(service, tokens)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
	})

	t.Run("refresh fails for a deleted user", func(t *testing.T) {
		service, usersRepo, user := setup(t, time.Hour)
		tokens := login(t, service)
		require.NoError(t, usersRepo.Delete(ctx, user.UUID))

		_, err := refresh(service, tokens)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
	})

	t.Run("a new login replaces the previous session", func(t *testing.T) {
		service, _, _ := setup(t, time.Hour)
		first := login(t, service)
		second := login(t, service)

		_, err := refresh(service, first)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
		_, err = refresh(service, second)
		assert.NoError(t, err)
	})

	t.Run("refresh fails once the session exceeds the max age", func(t *testing.T) {
		service, _, _ := setup(t, time.Nanosecond)
		tokens := login(t, service)

		_, err := refresh(service, tokens)
		assert.ErrorIs(t, err, services.ErrInvalidToken)
	})
}
