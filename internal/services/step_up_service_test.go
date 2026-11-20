package services_test

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
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	stepUpUserUUID    = "user-uuid"
	stepUpSessionUUID = "session-uuid"
	stepUpEmail       = "user@example.com"
)

var stepUpKey = []byte("test-secret-key")

type stepUpMocks struct {
	challenges *mocks.SessionChallengeRepositoryMock
	sessions   *mocks.SessionsRepositoryMock
	users      *mocks.UsersRepositoryMock
	emails     *mocks.EmailVerificationServiceMock
}

func newTestStepUpService() (domain.StepUpService, stepUpMocks) {
	m := stepUpMocks{
		challenges: new(mocks.SessionChallengeRepositoryMock),
		sessions:   new(mocks.SessionsRepositoryMock),
		users:      new(mocks.UsersRepositoryMock),
		emails:     new(mocks.EmailVerificationServiceMock),
	}
	service := services.NewStepUpService(m.challenges, m.sessions, m.users, newTransactorMock(), m.emails, stepUpKey)
	return service, m
}

func stepUpHash(sessionUUID string, code string) string {
	mac := hmac.New(sha256.New, stepUpKey)
	mac.Write([]byte("step-up:" + sessionUUID + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

func activeSession() *domain.UserSession {
	return &domain.UserSession{UUID: stepUpSessionUUID, UserUUID: stepUpUserUUID, ExpiresAt: time.Now().Add(time.Hour).Unix()}
}

func TestStepUpService_RequestCode(t *testing.T) {
	user := &domain.User{UUID: stepUpUserUUID, Email: stepUpEmail}

	t.Run("success", func(t *testing.T) {
		service, m := newTestStepUpService()
		var code string
		var stored domain.SessionChallenge
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(activeSession(), nil).Once()
		m.users.On("FindByUUID", stepUpUserUUID).Return(user, nil).Once()
		m.emails.On("SendStepUpCode", stepUpEmail, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			code = args.String(1)
		})
		m.challenges.On("Upsert", mock.Anything, domain.StepUpCooldown).Return(nil).Once().Run(func(args mock.Arguments) {
			stored = args.Get(0).(domain.SessionChallenge)
		})

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		require.NoError(t, err)
		assert.Regexp(t, `^\d{6}$`, code)
		assert.Equal(t, stepUpUserUUID, stored.UserUUID)
		assert.Equal(t, stepUpSessionUUID, stored.SessionUUID)
		assert.Equal(t, domain.SessionChallengeStepUp, stored.Purpose)
		assert.WithinDuration(t, time.Now().Add(domain.StepUpCodeTTL), time.Unix(stored.ExpiresAt, 0), 5*time.Second)
		assert.Equal(t, stepUpHash(stepUpSessionUUID, code), stored.CodeHash)
		m.challenges.AssertExpectations(t)
		m.emails.AssertExpectations(t)
	})

	t.Run("error - session not found", func(t *testing.T) {
		service, m := newTestStepUpService()
		notFound := domain.NewNotFoundError("sessions.notFound")
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(nil, notFound).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		assert.ErrorIs(t, err, notFound)
		m.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - session expired", func(t *testing.T) {
		service, m := newTestStepUpService()
		expired := activeSession()
		expired.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(expired, nil).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		var unauthorized *domain.UnauthorizedError
		assert.ErrorAs(t, err, &unauthorized)
		m.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - user lookup fails", func(t *testing.T) {
		service, m := newTestStepUpService()
		lookupErr := domain.NewNotFoundError("users.notFound")
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(activeSession(), nil).Once()
		m.users.On("FindByUUID", stepUpUserUUID).Return(nil, lookupErr).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		assert.ErrorIs(t, err, lookupErr)
	})

	t.Run("error - user failure cap reached", func(t *testing.T) {
		service, m := newTestStepUpService()
		locked := &domain.User{
			UUID:                      stepUpUserUUID,
			Email:                     stepUpEmail,
			StepUpFailures:            domain.StepUpMaxUserFailures,
			StepUpFailuresWindowStart: time.Now().Add(-time.Hour).Unix(),
		}
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(activeSession(), nil).Once()
		m.users.On("FindByUUID", stepUpUserUUID).Return(locked, nil).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		var tooMany *domain.TooManyRequestsError
		require.ErrorAs(t, err, &tooMany)
		assert.Equal(t, "auth.stepUp.userLocked", tooMany.Error())
		m.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - cooldown does not send email", func(t *testing.T) {
		service, m := newTestStepUpService()
		cooldown := domain.NewTooManyRequestsError("auth.stepUp.cooldown")
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(activeSession(), nil).Once()
		m.users.On("FindByUUID", stepUpUserUUID).Return(user, nil).Once()
		m.challenges.On("Upsert", mock.Anything, domain.StepUpCooldown).Return(cooldown).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		assert.ErrorIs(t, err, cooldown)
		m.emails.AssertNotCalled(t, "SendStepUpCode", mock.Anything, mock.Anything)
	})

	t.Run("error - email failure returns internal error", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(activeSession(), nil).Once()
		m.users.On("FindByUUID", stepUpUserUUID).Return(user, nil).Once()
		m.challenges.On("Upsert", mock.Anything, domain.StepUpCooldown).Return(nil).Once()
		m.emails.On("SendStepUpCode", stepUpEmail, mock.Anything).Return(errors.New("smtp down")).Once()
		m.challenges.On("Delete", stepUpSessionUUID, domain.SessionChallengeStepUp).Return(nil).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		var internal *domain.InternalServerError
		assert.ErrorAs(t, err, &internal)
		m.challenges.AssertCalled(t, "Delete", stepUpSessionUUID, domain.SessionChallengeStepUp)
	})

	t.Run("error - email failure with failing cleanup still returns the send error", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(activeSession(), nil).Once()
		m.users.On("FindByUUID", stepUpUserUUID).Return(user, nil).Once()
		m.challenges.On("Upsert", mock.Anything, domain.StepUpCooldown).Return(nil).Once()
		m.emails.On("SendStepUpCode", stepUpEmail, mock.Anything).Return(errors.New("smtp down")).Once()
		m.challenges.On("Delete", stepUpSessionUUID, domain.SessionChallengeStepUp).Return(errors.New("db down")).Once()

		err := service.RequestCode(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		var internal *domain.InternalServerError
		require.ErrorAs(t, err, &internal)
		assert.Equal(t, "auth.stepUp.sendFailed", internal.Error())
		m.challenges.AssertCalled(t, "Delete", stepUpSessionUUID, domain.SessionChallengeStepUp)
	})
}

func TestStepUpService_VerifyCode(t *testing.T) {
	const code = "123456"

	t.Run("success", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, code)}, nil).Once()
		m.users.On("RefundStepUpGuess", stepUpUserUUID).Return(nil).Once()
		m.challenges.On("Delete", stepUpSessionUUID, domain.SessionChallengeStepUp).Return(nil).Once()
		m.sessions.On("SetStepUpUntil", stepUpUserUUID, stepUpSessionUUID, mock.Anything).Return(nil).Once()

		until, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(domain.StepUpElevationWindow), time.Unix(until, 0), 5*time.Second)
		m.users.AssertExpectations(t)
		m.challenges.AssertExpectations(t)
		m.sessions.AssertExpectations(t)
	})

	t.Run("success - refund failure is only logged", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, code)}, nil).Once()
		m.users.On("RefundStepUpGuess", stepUpUserUUID).Return(errors.New("db down")).Once()
		m.challenges.On("Delete", stepUpSessionUUID, domain.SessionChallengeStepUp).Return(nil).Once()
		m.sessions.On("SetStepUpUntil", stepUpUserUUID, stepUpSessionUUID, mock.Anything).Return(nil).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		require.NoError(t, err)
		m.sessions.AssertExpectations(t)
	})

	t.Run("error - no challenge refunds the guess", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		noChallenge := domain.ErrStepUpNoChallenge
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).Return(nil, noChallenge).Once()
		m.users.On("RefundStepUpGuess", stepUpUserUUID).Return(nil).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		assert.ErrorIs(t, err, noChallenge)
		m.users.AssertExpectations(t)
		m.sessions.AssertNotCalled(t, "SetStepUpUntil", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - wrong code keeps the guess", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, "654321")}, nil).Once()
		m.sessions.On("IncrementStepUpFailures", stepUpUserUUID, stepUpSessionUUID).Return(domain.StepUpMaxSessionFailures-1, nil).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		var unauthorized *domain.UnauthorizedError
		require.ErrorAs(t, err, &unauthorized)
		assert.Equal(t, "auth.stepUp.invalidCode", unauthorized.Error())
		m.users.AssertNotCalled(t, "RefundStepUpGuess", mock.Anything)
		m.challenges.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
		m.sessions.AssertNotCalled(t, "SetStepUpUntil", mock.Anything, mock.Anything, mock.Anything)
		m.sessions.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	})

	t.Run("error - reaching the failure cap revokes the session", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, "654321")}, nil).Once()
		m.sessions.On("IncrementStepUpFailures", stepUpUserUUID, stepUpSessionUUID).Return(domain.StepUpMaxSessionFailures, nil).Once()
		m.sessions.On("Delete", stepUpUserUUID, stepUpSessionUUID).Return(nil).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		var unauthorized *domain.UnauthorizedError
		require.ErrorAs(t, err, &unauthorized)
		assert.Equal(t, "auth.stepUp.sessionRevoked", unauthorized.Error())
		m.sessions.AssertExpectations(t)
	})

	t.Run("error - revoking the session fails", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		deleteErr := errors.New("db down")
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, "654321")}, nil).Once()
		m.sessions.On("IncrementStepUpFailures", stepUpUserUUID, stepUpSessionUUID).Return(domain.StepUpMaxSessionFailures, nil).Once()
		m.sessions.On("Delete", stepUpUserUUID, stepUpSessionUUID).Return(deleteErr).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		assert.ErrorIs(t, err, deleteErr)
	})

	t.Run("error - counting the failure fails", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		incrementErr := errors.New("db down")
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, "654321")}, nil).Once()
		m.sessions.On("IncrementStepUpFailures", stepUpUserUUID, stepUpSessionUUID).Return(0, incrementErr).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		assert.ErrorIs(t, err, incrementErr)
		m.sessions.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	})

	t.Run("error - elevating the session fails", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(nil).Once()
		setErr := errors.New("db down")
		m.challenges.On("Attempt", stepUpUserUUID, stepUpSessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts).
			Return(&domain.SessionChallenge{CodeHash: stepUpHash(stepUpSessionUUID, code)}, nil).Once()
		m.users.On("RefundStepUpGuess", stepUpUserUUID).Return(nil).Once()
		m.challenges.On("Delete", stepUpSessionUUID, domain.SessionChallengeStepUp).Return(nil).Once()
		m.sessions.On("SetStepUpUntil", stepUpUserUUID, stepUpSessionUUID, mock.Anything).Return(setErr).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		assert.ErrorIs(t, err, setErr)
	})

	t.Run("error - user failure cap reached", func(t *testing.T) {
		service, m := newTestStepUpService()
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(domain.ErrStepUpUserLocked).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		var tooMany *domain.TooManyRequestsError
		require.ErrorAs(t, err, &tooMany)
		assert.Equal(t, "auth.stepUp.userLocked", tooMany.Error())
		m.challenges.AssertNotCalled(t, "Attempt", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - reserving the guess fails", func(t *testing.T) {
		service, m := newTestStepUpService()
		reserveErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		m.users.On("ReserveStepUpGuess", stepUpUserUUID, domain.StepUpUserFailureWindow).Return(reserveErr).Once()

		_, err := service.VerifyCode(context.Background(), stepUpUserUUID, stepUpSessionUUID, code)

		assert.ErrorIs(t, err, reserveErr)
		m.challenges.AssertNotCalled(t, "Attempt", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestStepUpService_IsElevated(t *testing.T) {
	cases := []struct {
		name    string
		session *domain.UserSession
		err     error
		want    bool
	}{
		{"success - elevated", func() *domain.UserSession {
			s := activeSession()
			s.StepUpUntil = time.Now().Add(time.Minute).Unix()
			return s
		}(), nil, true},
		{"not elevated - never verified", activeSession(), nil, false},
		{"not elevated - window elapsed", func() *domain.UserSession {
			s := activeSession()
			s.StepUpUntil = time.Now().Add(-time.Minute).Unix()
			return s
		}(), nil, false},
		{"not elevated - session expired", func() *domain.UserSession {
			s := activeSession()
			s.ExpiresAt = time.Now().Add(-time.Minute).Unix()
			s.StepUpUntil = time.Now().Add(time.Minute).Unix()
			return s
		}(), nil, false},
		{"not elevated - session missing", nil, domain.NewNotFoundError("sessions.notFound"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, m := newTestStepUpService()
			m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(tc.session, tc.err).Once()

			elevated, err := service.IsElevated(context.Background(), stepUpUserUUID, stepUpSessionUUID)

			require.NoError(t, err)
			assert.Equal(t, tc.want, elevated)
		})
	}

	t.Run("error - lookup failure", func(t *testing.T) {
		service, m := newTestStepUpService()
		internal := domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))
		m.sessions.On("FindByUUID", stepUpUserUUID, stepUpSessionUUID).Return(nil, internal).Once()

		_, err := service.IsElevated(context.Background(), stepUpUserUUID, stepUpSessionUUID)

		assert.ErrorIs(t, err, internal)
	})
}
