package integration_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStepUpService_VerifyCode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
	}

	const code = "123456"
	key := []byte("test-secret-key")

	setup := func(t *testing.T, setErr error) (domain.StepUpService, domain.SessionChallengeRepository, domain.SessionsRepository, *domain.UserSession) {
		t.Helper()
		ctx := context.Background()
		truncateTables(ctx, testDB)

		db := repositories.NewTxAwareDB(testDB)
		usersRepo := repositories.NewUsersPostgresRepository(db)
		sessionsRepo := repositories.NewSessionsPostgresRepository(db)
		stepUpRepo := repositories.NewSessionChallengesPostgresRepository(db)

		user, err := usersRepo.Create(ctx, domain.User{Name: "Step Up", Email: "stepup@example.com", Role: domain.RoleUser})
		require.NoError(t, err)
		session := seedSession(t, sessionsRepo, user.UUID, "jti")

		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("step-up:" + session.UUID + ":" + code))
		err = stepUpRepo.Upsert(ctx, domain.SessionChallenge{
			UserUUID:    user.UUID,
			SessionUUID: session.UUID,
			Purpose:     domain.SessionChallengeStepUp,
			CodeHash:    hex.EncodeToString(mac.Sum(nil)),
			ExpiresAt:   time.Now().Add(domain.StepUpCodeTTL).Unix(),
		}, domain.StepUpCooldown)
		require.NoError(t, err)

		serviceSessionsRepo := sessionsRepo
		if setErr != nil {
			serviceSessionsRepo = failingStepUpSessionsRepository{SessionsRepository: sessionsRepo, err: setErr}
		}
		service := services.NewStepUpService(
			stepUpRepo,
			serviceSessionsRepo,
			usersRepo,
			repositories.NewPostgresTransactor(testDB),
			new(mocks.EmailVerificationServiceMock),
			key,
			time.Now,
		)

		return service, stepUpRepo, sessionsRepo, session
	}

	challengeExists := func(t *testing.T, sessionUUID string) bool {
		t.Helper()
		var count int
		require.NoError(t, testDB.QueryRow(context.Background(),
			"SELECT count(*) FROM session_challenges WHERE session_uuid = $1 AND purpose = 'step_up'", sessionUUID).Scan(&count))
		return count == 1
	}

	t.Run("success", func(t *testing.T) {
		service, _, sessionsRepo, session := setup(t, nil)

		until, err := service.VerifyCode(context.Background(), session.UserUUID, session.UUID, code)

		require.NoError(t, err)
		assert.False(t, challengeExists(t, session.UUID))
		stored, err := sessionsRepo.FindByUUID(context.Background(), session.UserUUID, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, until, stored.StepUpUntil)
	})

	t.Run("error - elevating the session fails and keeps the challenge", func(t *testing.T) {
		setErr := errors.New("set failed")
		service, _, sessionsRepo, session := setup(t, setErr)

		_, err := service.VerifyCode(context.Background(), session.UserUUID, session.UUID, code)

		require.Error(t, err)
		assert.ErrorIs(t, err, setErr)
		assert.True(t, challengeExists(t, session.UUID))
		stored, err := sessionsRepo.FindByUUID(context.Background(), session.UserUUID, session.UUID)
		require.NoError(t, err)
		assert.Zero(t, stored.StepUpUntil)
	})
}
