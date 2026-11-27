package services

import (
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"time"

	"go-net-http-auth-base/internal/domain"
)

var ErrStepUpInvalidCode = domain.NewUnauthorizedError("auth.stepUp.invalidCode")

type stepUpService struct {
	challenges domain.SessionChallengeRepository
	sessions   domain.SessionsRepository
	users      domain.UsersRepository
	transactor domain.Transactor
	emails     domain.EmailVerificationService
	hmacKey    []byte
	now        func() time.Time
}

func NewStepUpService(
	challenges domain.SessionChallengeRepository,
	sessions domain.SessionsRepository,
	users domain.UsersRepository,
	transactor domain.Transactor,
	emails domain.EmailVerificationService,
	hmacKey []byte,
	now func() time.Time,
) domain.StepUpService {
	return &stepUpService{
		challenges: challenges,
		sessions:   sessions,
		users:      users,
		transactor: transactor,
		emails:     emails,
		hmacKey:    hmacKey,
		now:        now,
	}
}

func (s *stepUpService) RequestCode(ctx context.Context, userUUID string, sessionUUID string) error {
	session, err := s.sessions.FindByUUID(ctx, userUUID, sessionUUID)
	if err != nil {
		return err
	}
	if s.now().Unix() >= session.ExpiresAt {
		return ErrInvalidToken
	}

	user, err := s.users.FindByUUID(ctx, userUUID)
	if err != nil {
		return err
	}
	if isStepUpLocked(user, s.now()) {
		return domain.ErrStepUpUserLocked
	}

	code, err := generateOTP()
	if err != nil {
		return domain.NewInternalServerError("auth.stepUp.codeGenerationFailed", err)
	}

	err = s.challenges.Upsert(ctx, domain.SessionChallenge{
		UserUUID:    userUUID,
		SessionUUID: sessionUUID,
		Purpose:     domain.SessionChallengeStepUp,
		CodeHash:    s.hashCode(sessionUUID, code),
		ExpiresAt:   s.now().Add(domain.StepUpCodeTTL).Unix(),
	}, domain.StepUpCooldown)
	if err != nil {
		return err
	}

	return sendOrRollback(ctx, "auth.stepUp.sendFailed",
		func() error { return s.emails.SendStepUpCode(ctx, user.Email, code) },
		func() error { return s.challenges.Delete(ctx, sessionUUID, domain.SessionChallengeStepUp) },
	)
}

func (s *stepUpService) VerifyCode(ctx context.Context, userUUID string, sessionUUID string, code string) (int64, error) {
	if err := s.users.ReserveStepUpGuess(ctx, userUUID, domain.StepUpUserFailureWindow); err != nil {
		return 0, err
	}

	challenge, err := s.challenges.Attempt(ctx, userUUID, sessionUUID, domain.SessionChallengeStepUp, domain.StepUpMaxAttempts)
	if err != nil {
		s.refundGuess(ctx, userUUID)
		return 0, err
	}

	if !hmac.Equal([]byte(challenge.CodeHash), []byte(s.hashCode(sessionUUID, code))) {
		return 0, s.rejectWrongCode(ctx, userUUID, sessionUUID)
	}
	s.refundGuess(ctx, userUUID)

	until := s.now().Add(domain.StepUpElevationWindow)
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.challenges.Delete(ctx, sessionUUID, domain.SessionChallengeStepUp); err != nil {
			return err
		}
		return s.sessions.SetStepUpUntil(ctx, userUUID, sessionUUID, until)
	})
	if err != nil {
		return 0, err
	}
	return until.Unix(), nil
}

func (s *stepUpService) IsElevated(ctx context.Context, userUUID string, sessionUUID string) (bool, error) {
	session, err := s.sessions.FindByUUID(ctx, userUUID, sessionUUID)
	if err != nil {
		if _, ok := errors.AsType[*domain.NotFoundError](err); ok {
			return false, nil
		}
		return false, err
	}

	now := s.now().Unix()
	return now < session.ExpiresAt && now < session.StepUpUntil, nil
}

func (s *stepUpService) rejectWrongCode(ctx context.Context, userUUID string, sessionUUID string) error {
	failures, err := s.sessions.IncrementStepUpFailures(ctx, userUUID, sessionUUID)
	if err != nil {
		return err
	}
	if failures < domain.StepUpMaxSessionFailures {
		return ErrStepUpInvalidCode
	}

	if err := s.sessions.Delete(ctx, userUUID, sessionUUID); err != nil {
		return err
	}
	return domain.ErrStepUpSessionRevoked
}

func (s *stepUpService) refundGuess(ctx context.Context, userUUID string) {
	if err := s.users.RefundStepUpGuess(ctx, userUUID); err != nil {
		slog.ErrorContext(ctx, "step-up guess refund failed", "error", err, "user_uuid", userUUID)
	}
}

func (s *stepUpService) hashCode(sessionUUID string, code string) string {
	return hashOTP(s.hmacKey, "step-up:"+sessionUUID, code)
}

func isStepUpLocked(user *domain.User, now time.Time) bool {
	windowEnd := time.Unix(user.StepUpFailuresWindowStart, 0).Add(domain.StepUpUserFailureWindow)
	return user.StepUpFailures >= domain.StepUpMaxUserFailures && now.Before(windowEnd)
}
