package services_test

import (
	"context"
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

func TestNewEmailChangeService(t *testing.T) {
	f := newEmailChangeFixture()
	assert.NotNil(t, f.service)
}

var emailChangeKey = []byte("email-change-test-key")

type emailChangeFixture struct {
	service           domain.EmailChangeService
	repo              *mocks.UsersRepositoryMock
	sessions          *mocks.SessionsRepositoryMock
	authRepo          *mocks.AuthRepositoryMock
	challenges        *mocks.SessionChallengeRepositoryMock
	limiter           *mocks.EmailSendLimiterMock
	transactor        *mocks.TransactorMock
	emailVerification *mocks.EmailVerificationServiceMock
}

func newEmailChangeFixture() emailChangeFixture {
	f := emailChangeFixture{
		repo:              new(mocks.UsersRepositoryMock),
		sessions:          new(mocks.SessionsRepositoryMock),
		authRepo:          new(mocks.AuthRepositoryMock),
		challenges:        new(mocks.SessionChallengeRepositoryMock),
		limiter:           new(mocks.EmailSendLimiterMock),
		transactor:        newTransactorMock(),
		emailVerification: new(mocks.EmailVerificationServiceMock),
	}
	f.service = services.NewEmailChangeService(f.repo, f.emailVerification, f.sessions, f.authRepo, f.challenges, f.limiter, f.transactor, emailChangeKey, testClock)
	return f
}

func TestEmailChangeService_RequestEmailChange(t *testing.T) {
	const sessionUUID = "session-uuid"
	user := &domain.User{UUID: selfActor.UUID, Email: "old@example.com", EmailVersion: 2}

	expectAvailable := func(f emailChangeFixture, email string) {
		f.repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		f.repo.On("FindByEmail", email).Return(nil, domain.NewNotFoundError("users.notFound")).Once()
		f.repo.On("IsEmailReserved", email).Return(false, nil).Once()
	}
	expectUpsert := func(f emailChangeFixture) *string {
		var code string
		f.challenges.On("Upsert", mock.MatchedBy(func(c domain.SessionChallenge) bool {
			return c.UserUUID == selfActor.UUID &&
				c.SessionUUID == sessionUUID &&
				c.Purpose == domain.SessionChallengeEmailChange &&
				c.NewEmail == "new@example.com" &&
				c.EmailVersion == 2 &&
				c.CodeHash != "" &&
				c.ExpiresAt == testNow.Add(domain.EmailChangeCodeTTL).Unix()
		}), domain.EmailChangeCooldown).Return(nil).Once().Run(func(args mock.Arguments) {
			challenge := args.Get(0).(domain.SessionChallenge)
			f.emailVerification.On("SendEmailChangeCode", "new@example.com", mock.MatchedBy(func(sent string) bool {
				code = sent
				return services.HashOTP(emailChangeKey, "email-change:"+sessionUUID, sent) == challenge.CodeHash
			})).Return(nil).Once()
		})
		return &code
	}
	expectReserve := func(f emailChangeFixture, err error) {
		f.limiter.On("ReserveSend", "new@example.com", domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow).Return(err).Once()
	}

	t.Run("success stores the code hash for the session and mails the code to the normalized new email", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectAvailable(f, "new@example.com")
		code := expectUpsert(f)
		expectReserve(f, nil)

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "  New@Example.com ")

		require.NoError(t, err)
		assert.Len(t, *code, 6)
		f.repo.AssertExpectations(t)
		f.challenges.AssertExpectations(t)
		f.limiter.AssertExpectations(t)
		f.emailVerification.AssertExpectations(t)
	})

	t.Run("error - locked after a recent change", func(t *testing.T) {
		f := newEmailChangeFixture()
		locked := *user
		locked.EmailChangedAt = testNow.Add(-time.Hour).Unix()
		f.repo.On("FindByUUID", selfActor.UUID).Return(&locked, nil).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.emailChange.locked", conflictErr.Error())
		f.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - new email reserved by another user's change lock", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		f.repo.On("FindByEmail", "reserved@example.com").Return(nil, domain.NewNotFoundError("users.notFound")).Once()
		f.repo.On("IsEmailReserved", "reserved@example.com").Return(true, nil).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "reserved@example.com")

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
		f.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - unauthenticated actor", func(t *testing.T) {
		f := newEmailChangeFixture()

		err := f.service.RequestEmailChange(context.Background(), domain.Actor{}, sessionUUID, "new@example.com")

		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
		f.repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
	})

	t.Run("error - same email", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "OLD@example.com")

		var validationErr *domain.ValidationError
		require.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "users.emailChange.unchanged", validationErr.Error())
		f.repo.AssertNotCalled(t, "FindByEmail", mock.Anything)
	})

	t.Run("error - email taken", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		f.repo.On("FindByEmail", "taken@example.com").Return(&domain.User{UUID: "other"}, nil).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "taken@example.com")

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
		f.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - user lookup fails", func(t *testing.T) {
		f := newEmailChangeFixture()
		notFound := domain.NewNotFoundError("users.notFound")
		f.repo.On("FindByUUID", selfActor.UUID).Return(nil, notFound).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		assert.ErrorIs(t, err, notFound)
	})

	t.Run("error - email lookup fails", func(t *testing.T) {
		f := newEmailChangeFixture()
		dbErr := errors.New("db error")
		f.repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		f.repo.On("FindByEmail", "new@example.com").Return(nil, dbErr).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		assert.ErrorIs(t, err, dbErr)
		f.challenges.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
	})

	t.Run("error - cooldown", func(t *testing.T) {
		f := newEmailChangeFixture()
		cooldown := domain.NewTooManyRequestsError("users.emailChange.cooldown")
		expectAvailable(f, "new@example.com")
		f.challenges.On("Upsert", mock.Anything, domain.EmailChangeCooldown).Return(cooldown).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		assert.ErrorIs(t, err, cooldown)
		f.limiter.AssertNotCalled(t, "ReserveSend", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangeCode", mock.Anything, mock.Anything)
	})

	t.Run("error - send limit", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectAvailable(f, "new@example.com")
		expectUpsert(f)
		expectReserve(f, domain.ErrEmailSendLimit)

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		assert.ErrorIs(t, err, domain.ErrEmailSendLimit)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangeCode", mock.Anything, mock.Anything)
	})

	t.Run("error - send fails deletes the challenge", func(t *testing.T) {
		f := newEmailChangeFixture()
		sendErr := errors.New("smtp down")
		expectAvailable(f, "new@example.com")
		f.challenges.On("Upsert", mock.Anything, domain.EmailChangeCooldown).Return(nil).Once()
		expectReserve(f, nil)
		f.emailVerification.On("SendEmailChangeCode", "new@example.com", mock.Anything).Return(sendErr).Once()
		f.challenges.On("Delete", sessionUUID, domain.SessionChallengeEmailChange).Return(nil).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		var internalErr *domain.InternalServerError
		require.True(t, errors.As(err, &internalErr))
		assert.Equal(t, "users.emailChange.sendFailed", internalErr.Error())
		assert.ErrorIs(t, err, sendErr)
		f.challenges.AssertExpectations(t)
	})

	t.Run("error - send fails and cleanup fails still reports the send failure", func(t *testing.T) {
		f := newEmailChangeFixture()
		sendErr := errors.New("smtp down")
		expectAvailable(f, "new@example.com")
		f.challenges.On("Upsert", mock.Anything, domain.EmailChangeCooldown).Return(nil).Once()
		expectReserve(f, nil)
		f.emailVerification.On("SendEmailChangeCode", "new@example.com", mock.Anything).Return(sendErr).Once()
		f.challenges.On("Delete", sessionUUID, domain.SessionChallengeEmailChange).Return(errors.New("db error")).Once()

		err := f.service.RequestEmailChange(context.Background(), selfActor, sessionUUID, "new@example.com")

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailChangeService_ConfirmEmailChange(t *testing.T) {
	const sessionUUID = "session-uuid"
	const code = "123456"
	user := &domain.User{UUID: "user-uuid", Email: "old@example.com", EmailVersion: 3}
	actor := domain.Actor{UUID: "user-uuid", Role: domain.RoleUser}
	challenge := &domain.SessionChallenge{
		UserUUID:     "user-uuid",
		SessionUUID:  sessionUUID,
		Purpose:      domain.SessionChallengeEmailChange,
		NewEmail:     "new@example.com",
		EmailVersion: 3,
		CodeHash:     services.HashOTP(emailChangeKey, "email-change:"+sessionUUID, code),
	}
	changedAt := testNow.Unix()
	updated := &domain.User{UUID: "user-uuid", Email: "new@example.com", EmailVersion: 4, EmailChangedAt: changedAt}
	notice := domain.EmailChangeRevert{UserUUID: "user-uuid", OldEmail: "old@example.com", NewEmail: "new@example.com", Version: 4, ChangedAt: changedAt}

	expectFind := func(f emailChangeFixture) {
		f.challenges.On("Find", "user-uuid", sessionUUID, domain.SessionChallengeEmailChange).Return(challenge, nil).Once()
	}
	expectAttempt := func(f emailChangeFixture) {
		expectFind(f)
		f.limiter.On("ReserveCodeGuess", "new@example.com", domain.EmailCodeFailureWindow).Return(nil).Once()
		f.challenges.On("Attempt", "user-uuid", sessionUUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts).Return(challenge, nil).Once()
		f.limiter.On("RefundCodeGuess", "new@example.com").Return(nil).Maybe()
	}
	expectUpdate := func(f emailChangeFixture) {
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.MatchedBy(func(at *time.Time) bool {
			return at != nil && at.Equal(testNow)
		})).Return(updated, nil).Once()
		f.repo.On("IsEmailReserved", "new@example.com").Return(false, nil).Once()
	}

	t.Run("success updates the email, revokes every session and notifies the old address", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectAttempt(f)
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.NoError(t, err)
		assert.Equal(t, updated, result)
		f.repo.AssertExpectations(t)
		f.sessions.AssertExpectations(t)
		f.challenges.AssertExpectations(t)
		f.limiter.AssertExpectations(t)
		f.limiter.AssertCalled(t, "RefundCodeGuess", "new@example.com")
		f.emailVerification.AssertExpectations(t)
	})

	t.Run("success - an expired lock does not block", func(t *testing.T) {
		f := newEmailChangeFixture()
		locked := *user
		locked.EmailChangedAt = testNow.Add(-domain.EmailChangeLock - time.Hour).Unix()
		expectAttempt(f)
		f.repo.On("FindByUUID", "user-uuid").Return(&locked, nil).Once()
		f.repo.On("IsEmailReserved", "new@example.com").Return(false, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.Anything).Return(updated, nil).Once()
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(nil).Once()

		_, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.NoError(t, err)
	})

	t.Run("success - notice failure does not fail the change", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectAttempt(f)
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(errors.New("smtp down")).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.NoError(t, err)
		assert.Equal(t, updated, result)
	})

	t.Run("error - unauthenticated actor", func(t *testing.T) {
		f := newEmailChangeFixture()

		result, err := f.service.ConfirmEmailChange(context.Background(), domain.Actor{}, sessionUUID, code)

		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
		assert.Nil(t, result)
		f.challenges.AssertNotCalled(t, "Find", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - no challenge for the session", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.challenges.On("Find", "user-uuid", sessionUUID, domain.SessionChallengeEmailChange).Return(nil, domain.ErrEmailChangeNoChallenge).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
		assert.Nil(t, result)
		f.limiter.AssertNotCalled(t, "ReserveCodeGuess", mock.Anything, mock.Anything)
		f.repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
	})

	t.Run("error - a failed attempt refunds the reserved guess", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectFind(f)
		f.limiter.On("ReserveCodeGuess", "new@example.com", domain.EmailCodeFailureWindow).Return(nil).Once()
		f.challenges.On("Attempt", "user-uuid", sessionUUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts).Return(nil, domain.ErrEmailChangeNoChallenge).Once()
		f.limiter.On("RefundCodeGuess", "new@example.com").Return(nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
		assert.Nil(t, result)
		f.limiter.AssertExpectations(t)
		f.repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
	})

	t.Run("error - a challenge replaced for another address refunds the reserved guess", func(t *testing.T) {
		f := newEmailChangeFixture()
		replaced := *challenge
		replaced.NewEmail = "other@example.com"
		expectFind(f)
		f.limiter.On("ReserveCodeGuess", "new@example.com", domain.EmailCodeFailureWindow).Return(nil).Once()
		f.challenges.On("Attempt", "user-uuid", sessionUUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts).Return(&replaced, nil).Once()
		f.limiter.On("RefundCodeGuess", "new@example.com").Return(nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, domain.ErrEmailChangeNoChallenge)
		assert.Nil(t, result)
		f.limiter.AssertExpectations(t)
		f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - wrong code keeps the reserved guess for the new address and changes nothing", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectAttempt(f)

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, "000000")

		assert.ErrorIs(t, err, domain.ErrEmailChangeInvalidCode)
		assert.Nil(t, result)
		f.limiter.AssertExpectations(t)
		f.limiter.AssertNotCalled(t, "RefundCodeGuess", mock.Anything)
		f.transactor.AssertNotCalled(t, "WithinTx")
		f.repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
		f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
	})

	t.Run("success - a failed guess refund is only logged", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectFind(f)
		f.limiter.On("ReserveCodeGuess", "new@example.com", domain.EmailCodeFailureWindow).Return(nil).Once()
		f.challenges.On("Attempt", "user-uuid", sessionUUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts).Return(challenge, nil).Once()
		f.limiter.On("RefundCodeGuess", "new@example.com").Return(errors.New("db error")).Once()
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.NoError(t, err)
		assert.Equal(t, updated, result)
	})

	t.Run("error - address locked after too many wrong codes", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectFind(f)
		f.limiter.On("ReserveCodeGuess", "new@example.com", domain.EmailCodeFailureWindow).Return(domain.ErrEmailCodeLocked).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, domain.ErrEmailCodeLocked)
		assert.Nil(t, result)
		f.challenges.AssertNotCalled(t, "Attempt", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - guess reservation fails", func(t *testing.T) {
		f := newEmailChangeFixture()
		dbErr := errors.New("db error")
		expectFind(f)
		f.limiter.On("ReserveCodeGuess", "new@example.com", domain.EmailCodeFailureWindow).Return(dbErr).Once()

		_, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, dbErr)
		f.challenges.AssertNotCalled(t, "Attempt", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	staleCases := map[string]*domain.User{
		"version moved on (A to B to A)": {UUID: "user-uuid", Email: "old@example.com", EmailVersion: 5},
		"email changed meanwhile":        {UUID: "user-uuid", Email: "other@example.com", EmailVersion: 4},
	}
	for name, staleUser := range staleCases {
		t.Run("error - stale challenge: "+name, func(t *testing.T) {
			f := newEmailChangeFixture()
			expectAttempt(f)
			f.repo.On("FindByUUID", "user-uuid").Return(staleUser, nil).Once()

			result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

			var unauthorizedErr *domain.UnauthorizedError
			require.True(t, errors.As(err, &unauthorizedErr))
			assert.Equal(t, "users.emailChange.staleToken", unauthorizedErr.Error())
			assert.Nil(t, result)
			f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
		})
	}

	t.Run("error - locked after a recent change", func(t *testing.T) {
		f := newEmailChangeFixture()
		locked := *user
		locked.EmailChangedAt = testNow.Add(-time.Hour).Unix()
		expectAttempt(f)
		f.repo.On("FindByUUID", "user-uuid").Return(&locked, nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.emailChange.locked", conflictErr.Error())
		assert.Nil(t, result)
		f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - new email reserved by another user's change lock", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectAttempt(f)
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.Anything).Return(updated, nil).Once()
		f.repo.On("IsEmailReserved", "new@example.com").Return(true, nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
		assert.Nil(t, result)
		f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
	})

	t.Run("error - unknown user", func(t *testing.T) {
		f := newEmailChangeFixture()
		notFound := domain.NewNotFoundError("users.notFound")
		expectAttempt(f)
		f.repo.On("FindByUUID", "user-uuid").Return(nil, notFound).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, notFound)
		assert.Nil(t, result)
	})

	t.Run("error - update conflict", func(t *testing.T) {
		f := newEmailChangeFixture()
		conflict := domain.NewConflictError("users.email.conflict")
		expectAttempt(f)
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.Anything).Return(nil, conflict).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, conflict)
		assert.Nil(t, result)
		f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
	})

	t.Run("error - session revocation failure", func(t *testing.T) {
		f := newEmailChangeFixture()
		deleteErr := errors.New("db error")
		expectAttempt(f)
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(deleteErr).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), actor, sessionUUID, code)

		assert.ErrorIs(t, err, deleteErr)
		assert.Nil(t, result)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
	})
}

func TestEmailChangeService_RevertEmailChange(t *testing.T) {
	changedAt := testNow.Add(-time.Hour).Unix()
	revert := &domain.EmailChangeRevert{UserUUID: "user-uuid", OldEmail: "old@example.com", NewEmail: "new@example.com", Version: 4, ChangedAt: changedAt}
	user := &domain.User{UUID: "user-uuid", Email: "new@example.com", EmailVersion: 4, EmailChangedAt: changedAt}
	restored := &domain.User{UUID: "user-uuid", Email: "old@example.com", EmailVersion: 5}

	expectLoad := func(f emailChangeFixture) {
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(revert, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
	}

	t.Run("success restores the old email, clears the lock and revokes sessions and linked providers", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectLoad(f)
		f.repo.On("UpdateEmail", "user-uuid", "old@example.com", 4, (*time.Time)(nil)).Return(restored, nil).Once()
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.authRepo.On("DeleteOAuthProvidersCreatedSince", "user-uuid", time.Unix(changedAt, 0)).Return(nil).Once()

		result, err := f.service.RevertEmailChange(context.Background(), "token")

		assert.NoError(t, err)
		assert.Equal(t, restored, result)
		f.repo.AssertExpectations(t)
		f.sessions.AssertExpectations(t)
		f.authRepo.AssertExpectations(t)
	})

	t.Run("error - invalid token", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(nil, services.ErrInvalidToken).Once()

		result, err := f.service.RevertEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Nil(t, result)
	})

	staleCases := map[string]*domain.User{
		"replayed after the revert":     {UUID: "user-uuid", Email: "old@example.com", EmailVersion: 5},
		"email differs from the change": {UUID: "user-uuid", Email: "other@example.com", EmailVersion: 4},
	}
	for name, staleUser := range staleCases {
		t.Run("error - stale token: "+name, func(t *testing.T) {
			f := newEmailChangeFixture()
			f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(revert, nil).Once()
			f.repo.On("FindByUUID", "user-uuid").Return(staleUser, nil).Once()

			result, err := f.service.RevertEmailChange(context.Background(), "token")

			var unauthorizedErr *domain.UnauthorizedError
			require.True(t, errors.As(err, &unauthorizedErr))
			assert.Equal(t, "users.emailChange.staleToken", unauthorizedErr.Error())
			assert.Nil(t, result)
			f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}

	t.Run("error - unknown user", func(t *testing.T) {
		f := newEmailChangeFixture()
		notFound := domain.NewNotFoundError("users.notFound")
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(revert, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(nil, notFound).Once()

		result, err := f.service.RevertEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, notFound)
		assert.Nil(t, result)
	})

	t.Run("error - old email taken meanwhile", func(t *testing.T) {
		f := newEmailChangeFixture()
		conflict := domain.NewConflictError("users.email.conflict")
		expectLoad(f)
		f.repo.On("UpdateEmail", "user-uuid", "old@example.com", 4, (*time.Time)(nil)).Return(nil, conflict).Once()

		result, err := f.service.RevertEmailChange(context.Background(), "token")

		assert.Equal(t, conflict, err)
		assert.Nil(t, result)
		f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
	})

	t.Run("error - transaction step failure", func(t *testing.T) {
		f := newEmailChangeFixture()
		deleteErr := errors.New("db error")
		expectLoad(f)
		f.repo.On("UpdateEmail", "user-uuid", "old@example.com", 4, (*time.Time)(nil)).Return(restored, nil).Once()
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.authRepo.On("DeleteOAuthProvidersCreatedSince", "user-uuid", mock.Anything).Return(deleteErr).Once()

		result, err := f.service.RevertEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, deleteErr)
		assert.Nil(t, result)
	})
}
