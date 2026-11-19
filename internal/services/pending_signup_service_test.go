package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	signupPendingUUID = "0b7f3c8e-5d2a-4a8f-9c41-3f6f0d1e2a77"
	signupEmail       = "new@example.com"
)

var signupKey = []byte("test-secret-key")

type pendingSignupMocks struct {
	pending *mocks.PendingSignupRepositoryMock
	limiter *mocks.EmailSendLimiterMock
	users   *mocks.UsersRepositoryMock
	emails  *mocks.EmailVerificationServiceMock
}

func newTestPendingSignupService() (domain.PendingSignupService, pendingSignupMocks) {
	m := pendingSignupMocks{
		pending: new(mocks.PendingSignupRepositoryMock),
		limiter: new(mocks.EmailSendLimiterMock),
		users:   new(mocks.UsersRepositoryMock),
		emails:  new(mocks.EmailVerificationServiceMock),
	}
	service := services.NewPendingSignupService(m.pending, m.limiter, m.users, newTransactorMock(), m.emails, signupKey)
	return service, m
}

func signupHash(pendingUUID string, code string) string {
	return services.HashOTP(signupKey, "signup:"+pendingUUID, code)
}

func expectReserveSend(m pendingSignupMocks, email string, err error) {
	m.limiter.On("ReserveSend", email, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow).Return(err).Once()
}

func expectCreatePending(m pendingSignupMocks, stored *domain.PendingSignup) {
	created := &domain.PendingSignup{}
	m.pending.On("Create", mock.AnythingOfType("domain.PendingSignup")).Return(created, nil).Once().Run(func(args mock.Arguments) {
		*stored = args.Get(0).(domain.PendingSignup)
		*created = *stored
	})
}

func expectEmailAvailable(m pendingSignupMocks, email string) {
	m.users.On("FindByEmail", email).Return(nil, domain.NewNotFoundError("users.notFound")).Once()
	m.users.On("IsEmailReserved", email).Return(false, nil).Once()
}

func TestPendingSignupService_StartCredentials(t *testing.T) {
	dto := domain.CreateUserDTO{Name: "New User", Email: "  New@Example.com ", Password: "password123"}

	t.Run("success", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		var stored domain.PendingSignup
		var code string
		expectEmailAvailable(m, signupEmail)
		expectReserveSend(m, signupEmail, nil)
		expectCreatePending(m, &stored)
		m.emails.On("SendSignupCode", signupEmail, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			code = args.String(1)
		})

		pendingUUID, err := service.StartCredentials(context.Background(), dto)

		require.NoError(t, err)
		parsed, err := uuid.Parse(pendingUUID)
		require.NoError(t, err)
		assert.Equal(t, uuid.Version(7), parsed.Version())
		assert.Equal(t, pendingUUID, stored.UUID)
		assert.Equal(t, domain.PendingSignupKindCredentials, stored.Kind)
		assert.Equal(t, "New User", stored.Name)
		assert.Equal(t, signupEmail, stored.Email)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte(dto.Password)))
		assert.Regexp(t, `^\d{6}$`, code)
		assert.Equal(t, signupHash(pendingUUID, code), stored.CodeHash)
		assert.WithinDuration(t, time.Now().Add(domain.SignupCodeTTL), time.Unix(stored.CodeExpiresAt, 0), 5*time.Second)
		assert.WithinDuration(t, time.Now().Add(domain.PendingSignupTTL), time.Unix(stored.ExpiresAt, 0), 5*time.Second)
		m.pending.AssertExpectations(t)
		m.limiter.AssertExpectations(t)
		m.emails.AssertExpectations(t)
	})

	t.Run("error - email taken", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.users.On("FindByEmail", signupEmail).Return(&domain.User{UUID: "existing"}, nil).Once()

		_, err := service.StartCredentials(context.Background(), dto)

		var conflictErr *domain.ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Equal(t, "users.email.conflict", err.Error())
		m.limiter.AssertNotCalled(t, "ReserveSend", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		m.pending.AssertNotCalled(t, "Create", mock.Anything)
	})

	t.Run("error - email reserved", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.users.On("FindByEmail", signupEmail).Return(nil, domain.NewNotFoundError("users.notFound")).Once()
		m.users.On("IsEmailReserved", signupEmail).Return(true, nil).Once()

		_, err := service.StartCredentials(context.Background(), dto)

		assert.Equal(t, "users.email.conflict", err.Error())
		m.pending.AssertNotCalled(t, "Create", mock.Anything)
	})

	t.Run("error - user lookup fails", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		lookupErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		m.users.On("FindByEmail", signupEmail).Return(nil, lookupErr).Once()

		_, err := service.StartCredentials(context.Background(), dto)

		assert.Equal(t, lookupErr, err)
	})

	t.Run("error - send limit", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		expectEmailAvailable(m, signupEmail)
		expectReserveSend(m, signupEmail, domain.ErrEmailSendLimit)

		_, err := service.StartCredentials(context.Background(), dto)

		assert.Equal(t, domain.ErrEmailSendLimit, err)
		m.pending.AssertNotCalled(t, "Create", mock.Anything)
		m.emails.AssertNotCalled(t, "SendSignupCode", mock.Anything, mock.Anything)
	})

	t.Run("error - send failure deletes the pending signup", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		var stored domain.PendingSignup
		expectEmailAvailable(m, signupEmail)
		expectReserveSend(m, signupEmail, nil)
		expectCreatePending(m, &stored)
		m.emails.On("SendSignupCode", signupEmail, mock.Anything).Return(errors.New("smtp down")).Once()
		m.pending.On("Delete", mock.Anything).Return(nil).Once()

		_, err := service.StartCredentials(context.Background(), dto)

		var internalErr *domain.InternalServerError
		require.ErrorAs(t, err, &internalErr)
		assert.Equal(t, "auth.signup.sendFailed", err.Error())
		m.pending.AssertCalled(t, "Delete", stored.UUID)
	})
}

func TestPendingSignupService_StartOAuth(t *testing.T) {
	dto := domain.StartOAuthSignupDTO{Name: "OAuth User", Email: "New@Example.com", Provider: domain.OAuthProviderGitHub, ProviderUserID: "gh-1"}

	t.Run("success", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		var stored domain.PendingSignup
		var code string
		expectReserveSend(m, signupEmail, nil)
		expectCreatePending(m, &stored)
		m.emails.On("SendSignupCode", signupEmail, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			code = args.String(1)
		})

		pendingUUID, err := service.StartOAuth(context.Background(), dto)

		require.NoError(t, err)
		assert.Equal(t, pendingUUID, stored.UUID)
		assert.Equal(t, domain.PendingSignupKindOAuth, stored.Kind)
		assert.Equal(t, signupEmail, stored.Email)
		assert.Equal(t, domain.OAuthProviderGitHub, stored.Provider)
		assert.Equal(t, "gh-1", stored.ProviderUserID)
		assert.Empty(t, stored.PasswordHash)
		assert.Equal(t, signupHash(pendingUUID, code), stored.CodeHash)
		m.users.AssertNotCalled(t, "FindByEmail", mock.Anything)
	})

	t.Run("error - send limit", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		expectReserveSend(m, signupEmail, domain.ErrEmailSendLimit)

		_, err := service.StartOAuth(context.Background(), dto)

		assert.Equal(t, domain.ErrEmailSendLimit, err)
		m.pending.AssertNotCalled(t, "Create", mock.Anything)
	})
}

func TestPendingSignupService_Resend(t *testing.T) {
	pending := &domain.PendingSignup{UUID: signupPendingUUID, Email: signupEmail}

	t.Run("success", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		var storedHash, code string
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.pending.On("Resend", signupPendingUUID, mock.Anything, domain.SignupCodeTTL, domain.SignupResendCooldown).Return(pending, nil).Once().Run(func(args mock.Arguments) {
			storedHash = args.String(1)
		})
		expectReserveSend(m, signupEmail, nil)
		m.emails.On("SendSignupCode", signupEmail, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			code = args.String(1)
		})

		err := service.Resend(context.Background(), signupPendingUUID)

		require.NoError(t, err)
		assert.Equal(t, signupHash(signupPendingUUID, code), storedHash)
		m.limiter.AssertExpectations(t)
	})

	t.Run("error - no pending signup", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(nil, domain.ErrSignupNoPending).Once()

		err := service.Resend(context.Background(), signupPendingUUID)

		assert.Equal(t, domain.ErrSignupNoPending, err)
		m.emails.AssertNotCalled(t, "SendSignupCode", mock.Anything, mock.Anything)
	})

	t.Run("error - cooldown", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.pending.On("Resend", signupPendingUUID, mock.Anything, domain.SignupCodeTTL, domain.SignupResendCooldown).Return(nil, domain.ErrSignupCooldown).Once()

		err := service.Resend(context.Background(), signupPendingUUID)

		assert.Equal(t, domain.ErrSignupCooldown, err)
		m.limiter.AssertNotCalled(t, "ReserveSend", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		m.emails.AssertNotCalled(t, "SendSignupCode", mock.Anything, mock.Anything)
	})

	t.Run("error - send limit", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.pending.On("Resend", signupPendingUUID, mock.Anything, domain.SignupCodeTTL, domain.SignupResendCooldown).Return(pending, nil).Once()
		expectReserveSend(m, signupEmail, domain.ErrEmailSendLimit)

		err := service.Resend(context.Background(), signupPendingUUID)

		assert.Equal(t, domain.ErrEmailSendLimit, err)
		m.emails.AssertNotCalled(t, "SendSignupCode", mock.Anything, mock.Anything)
	})

	t.Run("error - send failure", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.pending.On("Resend", signupPendingUUID, mock.Anything, domain.SignupCodeTTL, domain.SignupResendCooldown).Return(pending, nil).Once()
		expectReserveSend(m, signupEmail, nil)
		m.emails.On("SendSignupCode", signupEmail, mock.Anything).Return(errors.New("smtp down")).Once()

		err := service.Resend(context.Background(), signupPendingUUID)

		assert.Equal(t, "auth.signup.sendFailed", err.Error())
	})
}

func TestPendingSignupService_Attempt(t *testing.T) {
	const code = "123456"
	pending := &domain.PendingSignup{UUID: signupPendingUUID, Email: signupEmail}
	attempted := &domain.PendingSignup{UUID: signupPendingUUID, Email: signupEmail, CodeHash: signupHash(signupPendingUUID, code), Attempts: 1}

	t.Run("success refunds the reserved guess", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.limiter.On("ReserveCodeGuess", signupEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.pending.On("Attempt", signupPendingUUID, domain.SignupMaxAttempts).Return(attempted, nil).Once()
		m.limiter.On("RefundCodeGuess", signupEmail).Return(nil).Once()

		err := service.Attempt(context.Background(), signupPendingUUID, code)

		require.NoError(t, err)
		m.limiter.AssertExpectations(t)
	})

	t.Run("success when the refund fails", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.limiter.On("ReserveCodeGuess", signupEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.pending.On("Attempt", signupPendingUUID, domain.SignupMaxAttempts).Return(attempted, nil).Once()
		m.limiter.On("RefundCodeGuess", signupEmail).Return(errors.New("db down")).Once()

		err := service.Attempt(context.Background(), signupPendingUUID, code)

		assert.NoError(t, err)
	})

	t.Run("error - wrong code keeps the reserved guess", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.limiter.On("ReserveCodeGuess", signupEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.pending.On("Attempt", signupPendingUUID, domain.SignupMaxAttempts).Return(attempted, nil).Once()

		err := service.Attempt(context.Background(), signupPendingUUID, "654321")

		assert.Equal(t, domain.ErrSignupInvalidCode, err)
		m.limiter.AssertNotCalled(t, "RefundCodeGuess", mock.Anything)
	})

	t.Run("error - code locked for the address", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.limiter.On("ReserveCodeGuess", signupEmail, domain.EmailCodeFailureWindow).Return(domain.ErrEmailCodeLocked).Once()

		err := service.Attempt(context.Background(), signupPendingUUID, code)

		assert.Equal(t, domain.ErrEmailCodeLocked, err)
		m.pending.AssertNotCalled(t, "Attempt", mock.Anything, mock.Anything)
	})

	t.Run("error - no pending signup", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(nil, domain.ErrSignupNoPending).Once()

		err := service.Attempt(context.Background(), signupPendingUUID, code)

		assert.Equal(t, domain.ErrSignupNoPending, err)
		m.limiter.AssertNotCalled(t, "ReserveCodeGuess", mock.Anything, mock.Anything)
	})

	t.Run("error - attempts exhausted or code expired refunds the guess", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("FindByUUID", signupPendingUUID).Return(pending, nil).Once()
		m.limiter.On("ReserveCodeGuess", signupEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.pending.On("Attempt", signupPendingUUID, domain.SignupMaxAttempts).Return(nil, domain.ErrSignupNoPending).Once()
		m.limiter.On("RefundCodeGuess", signupEmail).Return(nil).Once()

		err := service.Attempt(context.Background(), signupPendingUUID, code)

		assert.Equal(t, domain.ErrSignupNoPending, err)
		m.limiter.AssertExpectations(t)
	})
}

func TestPendingSignupService_Consume(t *testing.T) {
	const code = "123456"

	t.Run("success", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		consumed := &domain.PendingSignup{UUID: signupPendingUUID, Email: signupEmail}
		m.pending.On("Consume", signupPendingUUID, signupHash(signupPendingUUID, code)).Return(consumed, nil).Once()

		pending, err := service.Consume(context.Background(), signupPendingUUID, code)

		require.NoError(t, err)
		assert.Equal(t, consumed, pending)
	})

	t.Run("error - already consumed", func(t *testing.T) {
		service, m := newTestPendingSignupService()
		m.pending.On("Consume", signupPendingUUID, signupHash(signupPendingUUID, code)).Return(nil, domain.ErrSignupNoPending).Once()

		_, err := service.Consume(context.Background(), signupPendingUUID, code)

		assert.Equal(t, domain.ErrSignupNoPending, err)
	})
}
