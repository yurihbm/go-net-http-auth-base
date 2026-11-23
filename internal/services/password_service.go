package services

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type passwordService struct {
	resets     domain.PasswordResetRepository
	users      domain.UsersRepository
	sessions   domain.SessionsRepository
	limiter    domain.EmailSendLimiter
	transactor domain.Transactor
	emails     domain.EmailVerificationService
	hmacKey    []byte
}

func NewPasswordService(
	resets domain.PasswordResetRepository,
	users domain.UsersRepository,
	sessions domain.SessionsRepository,
	limiter domain.EmailSendLimiter,
	transactor domain.Transactor,
	emails domain.EmailVerificationService,
	hmacKey []byte,
) domain.PasswordService {
	return &passwordService{
		resets:     resets,
		users:      users,
		sessions:   sessions,
		limiter:    limiter,
		transactor: transactor,
		emails:     emails,
		hmacKey:    hmacKey,
	}
}

// RequestReset answers the same way for known and unknown addresses: an
// unknown one gets a UUID without a row, so the cookie never reveals whether
// the account exists.
func (s *passwordService) RequestReset(ctx context.Context, email string) (string, error) {
	email = normalizeEmail(email)
	if err := s.limiter.ReserveSend(ctx, email, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow); err != nil {
		return "", err
	}

	resetUUID, err := uuid.NewV7()
	if err != nil {
		return "", domain.NewInternalServerError("auth.passwordReset.codeGenerationFailed", err)
	}

	user, err := s.users.FindByEmail(ctx, email)
	var notFoundErr *domain.NotFoundError
	if errors.As(err, &notFoundErr) {
		return resetUUID.String(), nil
	}
	if err != nil {
		return "", err
	}

	code, err := generateOTP()
	if err != nil {
		return "", domain.NewInternalServerError("auth.passwordReset.codeGenerationFailed", err)
	}

	created, err := s.resets.Create(ctx, domain.PasswordReset{
		UUID:         resetUUID.String(),
		UserUUID:     user.UUID,
		Email:        user.Email,
		EmailVersion: user.EmailVersion,
		CodeHash:     s.hashCode(resetUUID.String(), code),
		ExpiresAt:    time.Now().Add(domain.PasswordResetTTL).Unix(),
	})
	if err != nil {
		return "", err
	}

	err = sendOrRollback(ctx, "auth.passwordReset.sendFailed",
		func() error { return s.emails.SendPasswordResetCode(ctx, user.Email, code) },
		func() error { return s.resets.Delete(ctx, created.UUID) },
	)
	if err != nil {
		return "", err
	}
	return created.UUID, nil
}

func (s *passwordService) ResetPassword(ctx context.Context, resetUUID string, dto domain.ResetPasswordDTO) (*domain.User, error) {
	reset, err := s.resets.FindByUUID(ctx, resetUUID)
	if err != nil {
		return nil, err
	}

	codeHash := s.hashCode(resetUUID, dto.Code)
	err = guessCode(ctx, s.limiter, reset.Email, codeHash, domain.ErrPasswordResetInvalidCode, func() (string, error) {
		attempted, err := s.resets.Attempt(ctx, resetUUID, domain.PasswordResetMaxAttempts)
		if err != nil {
			return "", err
		}
		return attempted.CodeHash, nil
	})
	if err != nil {
		return nil, err
	}

	passwordHash, err := hashPassword(dto.Password)
	if err != nil {
		return nil, err
	}

	var updated *domain.User
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		consumed, err := s.resets.Consume(ctx, resetUUID, codeHash)
		if err != nil {
			return err
		}

		// The reset is bound to the email version it was requested for, so an
		// email change in between makes it stop working.
		updated, err = s.users.UpdatePassword(ctx, consumed.UserUUID, passwordHash, &consumed.EmailVersion)
		if err != nil {
			return err
		}
		if err := s.sessions.DeleteAllByUser(ctx, updated.UUID); err != nil {
			return err
		}
		return s.resets.DeleteByUser(ctx, updated.UUID)
	})
	if err != nil {
		return nil, err
	}

	s.sendChangedNotice(ctx, updated)
	return updated, nil
}

func (s *passwordService) ChangePassword(ctx context.Context, actor domain.Actor, sessionUUID string, dto domain.ChangePasswordDTO) error {
	if actor.UUID == "" {
		return domain.NewUnauthorizedError("users.password.unauthorized")
	}

	passwordHash, err := hashPassword(dto.NewPassword)
	if err != nil {
		return err
	}

	var updated *domain.User
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		updated, err = s.users.UpdatePassword(ctx, actor.UUID, passwordHash, nil)
		if err != nil {
			return err
		}
		if err := s.sessions.DeleteOthersByUser(ctx, updated.UUID, sessionUUID); err != nil {
			return err
		}
		return s.resets.DeleteByUser(ctx, updated.UUID)
	})
	if err != nil {
		return err
	}

	s.sendChangedNotice(ctx, updated)
	return nil
}

func (s *passwordService) sendChangedNotice(ctx context.Context, user *domain.User) {
	if err := s.emails.SendPasswordChangedNotice(ctx, user.Email); err != nil {
		slog.ErrorContext(ctx, "password changed notice failed", "error", err, "user_uuid", user.UUID)
	}
}

func (s *passwordService) hashCode(resetUUID string, code string) string {
	return hashOTP(s.hmacKey, "password-reset:"+resetUUID, code)
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", domain.NewInternalServerError("users.password.hashingFailed", err)
	}
	return string(hash), nil
}
