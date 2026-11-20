package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"go-net-http-auth-base/internal/domain"
)

var ErrStepUpInvalidCode = domain.NewUnauthorizedError("auth.stepUp.invalidCode")

type stepUpService struct {
	challenges domain.StepUpRepository
	sessions   domain.SessionsRepository
	users      domain.UsersRepository
	transactor domain.Transactor
	emails     domain.EmailVerificationService
	hmacKey    []byte
}

func NewStepUpService(
	challenges domain.StepUpRepository,
	sessions domain.SessionsRepository,
	users domain.UsersRepository,
	transactor domain.Transactor,
	emails domain.EmailVerificationService,
	hmacKey []byte,
) domain.StepUpService {
	return &stepUpService{
		challenges: challenges,
		sessions:   sessions,
		users:      users,
		transactor: transactor,
		emails:     emails,
		hmacKey:    hmacKey,
	}
}

func (s *stepUpService) RequestCode(ctx context.Context, userUUID string, sessionUUID string) error {
	session, err := s.sessions.FindByUUID(ctx, userUUID, sessionUUID)
	if err != nil {
		return err
	}
	if time.Now().Unix() >= session.ExpiresAt {
		return ErrInvalidToken
	}

	user, err := s.users.FindByUUID(ctx, userUUID)
	if err != nil {
		return err
	}
	if isStepUpLocked(user) {
		return domain.ErrStepUpUserLocked
	}

	code, err := generateStepUpCode()
	if err != nil {
		return domain.NewInternalServerError("auth.stepUp.codeGenerationFailed", err)
	}

	_, err = s.challenges.Upsert(ctx, domain.StepUpChallenge{
		UserUUID:    userUUID,
		SessionUUID: sessionUUID,
		CodeHash:    s.hashCode(sessionUUID, code),
		ExpiresAt:   time.Now().Add(domain.StepUpCodeTTL).Unix(),
	}, domain.StepUpCooldown)
	if err != nil {
		return err
	}

	if err := s.emails.SendStepUpCode(ctx, user.Email, code); err != nil {
		if deleteErr := s.challenges.Delete(ctx, sessionUUID); deleteErr != nil {
			slog.ErrorContext(ctx, "step-up challenge cleanup failed", "error", deleteErr, "user_uuid", userUUID)
		}
		return domain.NewInternalServerError("auth.stepUp.sendFailed", err)
	}
	return nil
}

func (s *stepUpService) VerifyCode(ctx context.Context, userUUID string, sessionUUID string, code string) (int64, error) {
	if err := s.users.ReserveStepUpGuess(ctx, userUUID, domain.StepUpUserFailureWindow); err != nil {
		return 0, err
	}

	challenge, err := s.challenges.Attempt(ctx, userUUID, sessionUUID, domain.StepUpMaxAttempts)
	if err != nil {
		s.refundGuess(ctx, userUUID)
		return 0, err
	}

	if !hmac.Equal([]byte(challenge.CodeHash), []byte(s.hashCode(sessionUUID, code))) {
		return 0, s.rejectWrongCode(ctx, userUUID, sessionUUID)
	}
	s.refundGuess(ctx, userUUID)

	until := time.Now().Add(domain.StepUpElevationWindow)
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.challenges.Delete(ctx, sessionUUID); err != nil {
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
		var notFound *domain.NotFoundError
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, err
	}

	now := time.Now().Unix()
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
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(sessionUUID + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

func isStepUpLocked(user *domain.User) bool {
	windowEnd := time.Unix(user.StepUpFailuresWindowStart, 0).Add(domain.StepUpUserFailureWindow)
	return user.StepUpFailures >= domain.StepUpMaxUserFailures && time.Now().Before(windowEnd)
}

func generateStepUpCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
