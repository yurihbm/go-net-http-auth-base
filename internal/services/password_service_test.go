package services_test

import (
	"context"
	"errors"
	"testing"

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
	passwordUserUUID  = "0c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f"
	passwordResetUUID = "1d2e3f4a-5b6c-4d7e-8f90-1b2c3d4e5f60"
	passwordEmail     = "user@example.com"
)

type passwordMocks struct {
	resets   *mocks.PasswordResetRepositoryMock
	users    *mocks.UsersRepositoryMock
	sessions *mocks.SessionsRepositoryMock
	limiter  *mocks.EmailSendLimiterMock
	emails   *mocks.EmailVerificationServiceMock
}

func newTestPasswordService() (domain.PasswordService, passwordMocks) {
	m := passwordMocks{
		resets:   new(mocks.PasswordResetRepositoryMock),
		users:    new(mocks.UsersRepositoryMock),
		sessions: new(mocks.SessionsRepositoryMock),
		limiter:  new(mocks.EmailSendLimiterMock),
		emails:   new(mocks.EmailVerificationServiceMock),
	}
	service := services.NewPasswordService(m.resets, m.users, m.sessions, m.limiter, newTransactorMock(), m.emails, signupKey, testClock)
	return service, m
}

func passwordTestUser() *domain.User {
	return &domain.User{UUID: passwordUserUUID, Email: passwordEmail, EmailVersion: 2}
}

func TestPasswordService_RequestReset(t *testing.T) {
	expectSend := func(m passwordMocks, err error) {
		m.limiter.On("ReserveSend", passwordEmail, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow).Return(err).Once()
	}

	t.Run("success known address stores the reset and emails the code", func(t *testing.T) {
		service, m := newTestPasswordService()
		var stored domain.PasswordReset
		var code string
		expectSend(m, nil)
		m.users.On("FindByEmail", passwordEmail).Return(passwordTestUser(), nil).Once()
		created := &domain.PasswordReset{}
		m.resets.On("Create", mock.AnythingOfType("domain.PasswordReset")).Return(created, nil).Once().Run(func(args mock.Arguments) {
			stored = args.Get(0).(domain.PasswordReset)
			*created = stored
		})
		m.emails.On("SendPasswordResetCode", passwordEmail, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			code = args.String(1)
		})

		resetUUID, err := service.RequestReset(context.Background(), "  User@Example.com ")

		require.NoError(t, err)
		parsed, err := uuid.Parse(stored.UUID)
		require.NoError(t, err)
		assert.Equal(t, uuid.Version(7), parsed.Version())
		assert.Equal(t, passwordUserUUID, stored.UserUUID)
		assert.Equal(t, passwordEmail, stored.Email)
		assert.Equal(t, 2, stored.EmailVersion)
		assert.Regexp(t, `^\d{6}$`, code)
		assert.Equal(t, services.HashOTP(signupKey, "password-reset:"+stored.UUID, code), stored.CodeHash)
		assert.Equal(t, testNow.Add(domain.PasswordResetTTL).Unix(), stored.ExpiresAt)
		assert.Equal(t, stored.UUID, resetUUID)
		m.resets.AssertExpectations(t)
		m.emails.AssertExpectations(t)
	})

	t.Run("success OAuth-only user gets a reset like any other", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectSend(m, nil)
		m.users.On("FindByEmail", passwordEmail).Return(&domain.User{UUID: passwordUserUUID, Email: passwordEmail}, nil).Once()
		m.resets.On("Create", mock.Anything).Return(&domain.PasswordReset{UUID: passwordResetUUID}, nil).Once()
		m.emails.On("SendPasswordResetCode", passwordEmail, mock.Anything).Return(nil).Once()

		resetUUID, err := service.RequestReset(context.Background(), passwordEmail)

		require.NoError(t, err)
		assert.Equal(t, passwordResetUUID, resetUUID)
	})

	t.Run("success unknown address returns a UUID without a row or an email", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectSend(m, nil)
		m.users.On("FindByEmail", passwordEmail).Return(nil, domain.NewNotFoundError("users.notFound")).Once()

		resetUUID, err := service.RequestReset(context.Background(), passwordEmail)

		require.NoError(t, err)
		parsed, err := uuid.Parse(resetUUID)
		require.NoError(t, err)
		assert.Equal(t, uuid.Version(7), parsed.Version())
		m.resets.AssertNotCalled(t, "Create", mock.Anything)
		m.emails.AssertNotCalled(t, "SendPasswordResetCode", mock.Anything, mock.Anything)
	})

	t.Run("error - send limit applies to unknown addresses too", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectSend(m, domain.ErrEmailSendLimit)

		_, err := service.RequestReset(context.Background(), passwordEmail)

		assert.ErrorIs(t, err, domain.ErrEmailSendLimit)
		m.users.AssertNotCalled(t, "FindByEmail", mock.Anything)
	})

	t.Run("error - lookup fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		lookupErr := domain.NewInternalServerError("users.internalServerError", errors.New("db down"))
		expectSend(m, nil)
		m.users.On("FindByEmail", passwordEmail).Return(nil, lookupErr).Once()

		_, err := service.RequestReset(context.Background(), passwordEmail)

		assert.ErrorIs(t, err, lookupErr)
	})

	t.Run("error - create fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		createErr := domain.NewInternalServerError("auth.passwordReset.internalServerError", errors.New("db down"))
		expectSend(m, nil)
		m.users.On("FindByEmail", passwordEmail).Return(passwordTestUser(), nil).Once()
		m.resets.On("Create", mock.Anything).Return(nil, createErr).Once()

		_, err := service.RequestReset(context.Background(), passwordEmail)

		assert.ErrorIs(t, err, createErr)
		m.emails.AssertNotCalled(t, "SendPasswordResetCode", mock.Anything, mock.Anything)
	})

	t.Run("error - failed send deletes the reset", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectSend(m, nil)
		m.users.On("FindByEmail", passwordEmail).Return(passwordTestUser(), nil).Once()
		m.resets.On("Create", mock.Anything).Return(&domain.PasswordReset{UUID: passwordResetUUID}, nil).Once()
		m.emails.On("SendPasswordResetCode", passwordEmail, mock.Anything).Return(errors.New("smtp down")).Once()
		m.resets.On("Delete", passwordResetUUID).Return(nil).Once()

		_, err := service.RequestReset(context.Background(), passwordEmail)

		var internalErr *domain.InternalServerError
		require.ErrorAs(t, err, &internalErr)
		assert.Equal(t, "auth.passwordReset.sendFailed", err.Error())
		m.resets.AssertExpectations(t)
	})
}

func TestPasswordService_ResetPassword(t *testing.T) {
	const code = "123456"
	dto := domain.ResetPasswordDTO{Code: code, Password: "new-password-1"}
	storedReset := func() *domain.PasswordReset {
		return &domain.PasswordReset{
			UUID:         passwordResetUUID,
			UserUUID:     passwordUserUUID,
			Email:        passwordEmail,
			EmailVersion: 2,
			CodeHash:     services.HashOTP(signupKey, "password-reset:"+passwordResetUUID, code),
		}
	}
	expectGuess := func(m passwordMocks) {
		m.resets.On("FindByUUID", passwordResetUUID).Return(storedReset(), nil).Once()
		m.limiter.On("ReserveCodeGuess", passwordEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.resets.On("Attempt", passwordResetUUID, domain.PasswordResetMaxAttempts).Return(storedReset(), nil).Once()
		m.limiter.On("RefundCodeGuess", passwordEmail).Return(nil).Once()
	}
	expectConsume := func(m passwordMocks) {
		m.resets.On("Consume", passwordResetUUID, storedReset().CodeHash).Return(storedReset(), nil).Once()
	}

	t.Run("success updates the password, revokes every session and sends the notice", func(t *testing.T) {
		service, m := newTestPasswordService()
		var hash string
		expectGuess(m)
		expectConsume(m)
		version := 2
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, &version).Return(passwordTestUser(), nil).Once().Run(func(args mock.Arguments) {
			hash = args.String(1)
		})
		m.sessions.On("DeleteAllByUser", passwordUserUUID).Return(nil).Once()
		m.resets.On("DeleteByUser", passwordUserUUID).Return(nil).Once()
		m.emails.On("SendPasswordChangedNotice", passwordEmail).Return(nil).Once()

		user, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		require.NoError(t, err)
		assert.Equal(t, passwordUserUUID, user.UUID)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(dto.Password)))
		m.sessions.AssertExpectations(t)
		m.resets.AssertExpectations(t)
		m.emails.AssertExpectations(t)
		m.limiter.AssertExpectations(t)
	})

	t.Run("success even when the notice fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectGuess(m)
		expectConsume(m)
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, mock.Anything).Return(passwordTestUser(), nil).Once()
		m.sessions.On("DeleteAllByUser", passwordUserUUID).Return(nil).Once()
		m.resets.On("DeleteByUser", passwordUserUUID).Return(nil).Once()
		m.emails.On("SendPasswordChangedNotice", passwordEmail).Return(errors.New("smtp down")).Once()

		user, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		require.NoError(t, err)
		assert.NotNil(t, user)
	})

	t.Run("error - unknown reset", func(t *testing.T) {
		service, m := newTestPasswordService()
		m.resets.On("FindByUUID", passwordResetUUID).Return(nil, domain.ErrPasswordResetInvalidCode).Once()

		user, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		assert.Nil(t, user)
		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		m.limiter.AssertNotCalled(t, "ReserveCodeGuess", mock.Anything, mock.Anything)
	})

	t.Run("error - wrong code keeps the guess counted and changes nothing", func(t *testing.T) {
		service, m := newTestPasswordService()
		m.resets.On("FindByUUID", passwordResetUUID).Return(storedReset(), nil).Once()
		m.limiter.On("ReserveCodeGuess", passwordEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.resets.On("Attempt", passwordResetUUID, domain.PasswordResetMaxAttempts).Return(storedReset(), nil).Once()

		user, err := service.ResetPassword(context.Background(), passwordResetUUID, domain.ResetPasswordDTO{Code: "000000", Password: dto.Password})

		assert.Nil(t, user)
		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		m.limiter.AssertNotCalled(t, "RefundCodeGuess", mock.Anything)
		m.users.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - locked address", func(t *testing.T) {
		service, m := newTestPasswordService()
		m.resets.On("FindByUUID", passwordResetUUID).Return(storedReset(), nil).Once()
		m.limiter.On("ReserveCodeGuess", passwordEmail, domain.EmailCodeFailureWindow).Return(domain.ErrEmailCodeLocked).Once()

		_, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		assert.ErrorIs(t, err, domain.ErrEmailCodeLocked)
		m.resets.AssertNotCalled(t, "Attempt", mock.Anything, mock.Anything)
	})

	t.Run("error - out of attempts", func(t *testing.T) {
		service, m := newTestPasswordService()
		m.resets.On("FindByUUID", passwordResetUUID).Return(storedReset(), nil).Once()
		m.limiter.On("ReserveCodeGuess", passwordEmail, domain.EmailCodeFailureWindow).Return(nil).Once()
		m.resets.On("Attempt", passwordResetUUID, domain.PasswordResetMaxAttempts).Return(nil, domain.ErrPasswordResetInvalidCode).Once()
		m.limiter.On("RefundCodeGuess", passwordEmail).Return(nil).Once()

		_, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
	})

	t.Run("error - stale email version", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectGuess(m)
		expectConsume(m)
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, mock.Anything).Return(nil, domain.ErrPasswordResetInvalidCode).Once()

		user, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		assert.Nil(t, user)
		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		m.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
		m.emails.AssertNotCalled(t, "SendPasswordChangedNotice", mock.Anything)
	})

	t.Run("error - consume fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectGuess(m)
		m.resets.On("Consume", passwordResetUUID, mock.Anything).Return(nil, domain.ErrPasswordResetInvalidCode).Once()

		_, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		assert.ErrorIs(t, err, domain.ErrPasswordResetInvalidCode)
		m.users.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - revoking sessions fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		sessionsErr := errors.New("db down")
		expectGuess(m)
		expectConsume(m)
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, mock.Anything).Return(passwordTestUser(), nil).Once()
		m.sessions.On("DeleteAllByUser", passwordUserUUID).Return(sessionsErr).Once()

		_, err := service.ResetPassword(context.Background(), passwordResetUUID, dto)

		assert.ErrorIs(t, err, sessionsErr)
		m.emails.AssertNotCalled(t, "SendPasswordChangedNotice", mock.Anything)
	})

	t.Run("error - password too long to hash", func(t *testing.T) {
		service, m := newTestPasswordService()
		expectGuess(m)

		_, err := service.ResetPassword(context.Background(), passwordResetUUID, domain.ResetPasswordDTO{Code: code, Password: string(make([]byte, 80))})

		var internalErr *domain.InternalServerError
		require.ErrorAs(t, err, &internalErr)
		assert.Equal(t, "users.password.hashingFailed", err.Error())
		m.resets.AssertNotCalled(t, "Consume", mock.Anything, mock.Anything)
	})
}

func TestPasswordService_ChangePassword(t *testing.T) {
	actor := domain.Actor{UUID: passwordUserUUID, Role: domain.RoleUser}
	dto := domain.ChangePasswordDTO{NewPassword: "new-password-1"}
	const sessionUUID = "2e3f4a5b-6c7d-4e8f-9012-2c3d4e5f6071"

	t.Run("success keeps only the current session", func(t *testing.T) {
		service, m := newTestPasswordService()
		var hash string
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, (*int)(nil)).Return(passwordTestUser(), nil).Once().Run(func(args mock.Arguments) {
			hash = args.String(1)
		})
		m.sessions.On("DeleteOthersByUser", passwordUserUUID, sessionUUID).Return(nil).Once()
		m.resets.On("DeleteByUser", passwordUserUUID).Return(nil).Once()
		m.emails.On("SendPasswordChangedNotice", passwordEmail).Return(nil).Once()

		err := service.ChangePassword(context.Background(), actor, sessionUUID, dto)

		require.NoError(t, err)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(dto.NewPassword)))
		m.sessions.AssertExpectations(t)
		m.resets.AssertExpectations(t)
		m.emails.AssertExpectations(t)
	})

	t.Run("success even when the notice fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, (*int)(nil)).Return(passwordTestUser(), nil).Once()
		m.sessions.On("DeleteOthersByUser", passwordUserUUID, sessionUUID).Return(nil).Once()
		m.resets.On("DeleteByUser", passwordUserUUID).Return(nil).Once()
		m.emails.On("SendPasswordChangedNotice", passwordEmail).Return(errors.New("smtp down")).Once()

		assert.NoError(t, service.ChangePassword(context.Background(), actor, sessionUUID, dto))
	})

	t.Run("error - unauthenticated actor", func(t *testing.T) {
		service, m := newTestPasswordService()

		err := service.ChangePassword(context.Background(), domain.Actor{}, sessionUUID, dto)

		var unauthorizedErr *domain.UnauthorizedError
		assert.ErrorAs(t, err, &unauthorizedErr)
		m.users.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - hashing fails", func(t *testing.T) {
		service, m := newTestPasswordService()

		err := service.ChangePassword(context.Background(), actor, sessionUUID, domain.ChangePasswordDTO{NewPassword: string(make([]byte, 80))})

		var internalErr *domain.InternalServerError
		require.ErrorAs(t, err, &internalErr)
		assert.Equal(t, "users.password.hashingFailed", err.Error())
		m.users.AssertNotCalled(t, "UpdatePassword", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - update fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		updateErr := errors.New("db down")
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, (*int)(nil)).Return(nil, updateErr).Once()

		err := service.ChangePassword(context.Background(), actor, sessionUUID, dto)

		assert.ErrorIs(t, err, updateErr)
		m.sessions.AssertNotCalled(t, "DeleteOthersByUser", mock.Anything, mock.Anything)
		m.emails.AssertNotCalled(t, "SendPasswordChangedNotice", mock.Anything)
	})

	t.Run("error - revoking other sessions fails", func(t *testing.T) {
		service, m := newTestPasswordService()
		sessionsErr := errors.New("db down")
		m.users.On("UpdatePassword", passwordUserUUID, mock.Anything, (*int)(nil)).Return(passwordTestUser(), nil).Once()
		m.sessions.On("DeleteOthersByUser", passwordUserUUID, sessionUUID).Return(sessionsErr).Once()

		err := service.ChangePassword(context.Background(), actor, sessionUUID, dto)

		assert.ErrorIs(t, err, sessionsErr)
		m.emails.AssertNotCalled(t, "SendPasswordChangedNotice", mock.Anything)
	})
}
