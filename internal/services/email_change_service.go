package services

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go-net-http-auth-base/internal/domain"
)

type emailChangeService struct {
	repo              domain.UsersRepository
	emailVerification domain.EmailVerificationService
	sessionsRepo      domain.SessionsRepository
	authRepo          domain.AuthRepository
	challenges        domain.SessionChallengeRepository
	limiter           domain.EmailSendLimiter
	transactor        domain.Transactor
	hmacKey           []byte
}

func NewEmailChangeService(
	repo domain.UsersRepository,
	emailVerification domain.EmailVerificationService,
	sessionsRepo domain.SessionsRepository,
	authRepo domain.AuthRepository,
	challenges domain.SessionChallengeRepository,
	limiter domain.EmailSendLimiter,
	transactor domain.Transactor,
	hmacKey []byte,
) domain.EmailChangeService {
	return &emailChangeService{
		repo:              repo,
		emailVerification: emailVerification,
		sessionsRepo:      sessionsRepo,
		authRepo:          authRepo,
		challenges:        challenges,
		limiter:           limiter,
		transactor:        transactor,
		hmacKey:           hmacKey,
	}
}

func (s *emailChangeService) RequestEmailChange(ctx context.Context, actor domain.Actor, sessionUUID string, email string) error {
	if actor.UUID == "" {
		return domain.NewUnauthorizedError("users.emailChange.unauthorized")
	}

	user, err := s.repo.FindByUUID(ctx, actor.UUID)
	if err != nil {
		return err
	}

	if isEmailChangeLocked(user) {
		return domain.NewConflictError("users.emailChange.locked")
	}

	newEmail := normalizeEmail(email)
	if newEmail == user.Email {
		return domain.NewValidationError("users.emailChange.unchanged", map[string]string{
			"email": "must differ from the current email",
		})
	}

	existing, err := s.repo.FindByEmail(ctx, newEmail)
	var notFoundErr *domain.NotFoundError
	if err != nil && !errors.As(err, &notFoundErr) {
		return err
	}
	if existing != nil {
		return domain.NewConflictError("users.email.conflict")
	}

	if err := ensureEmailNotReserved(ctx, s.repo, newEmail); err != nil {
		return err
	}

	code, err := generateOTP()
	if err != nil {
		return domain.NewInternalServerError("users.emailChange.codeGenerationFailed", err)
	}

	// The new code only replaces the old one when the address may receive another email.
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		err := s.challenges.Upsert(ctx, domain.SessionChallenge{
			UserUUID:     user.UUID,
			SessionUUID:  sessionUUID,
			Purpose:      domain.SessionChallengeEmailChange,
			NewEmail:     newEmail,
			EmailVersion: user.EmailVersion,
			CodeHash:     s.hashEmailChangeCode(sessionUUID, code),
			ExpiresAt:    time.Now().Add(domain.EmailChangeCodeTTL).Unix(),
		}, domain.EmailChangeCooldown)
		if err != nil {
			return err
		}
		return s.limiter.ReserveSend(ctx, newEmail, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow)
	})
	if err != nil {
		return err
	}

	return sendOrRollback(ctx, "users.emailChange.sendFailed",
		func() error { return s.emailVerification.SendEmailChangeCode(ctx, newEmail, code) },
		func() error { return s.challenges.Delete(ctx, sessionUUID, domain.SessionChallengeEmailChange) },
	)
}

func (s *emailChangeService) ConfirmEmailChange(ctx context.Context, actor domain.Actor, sessionUUID string, code string) (*domain.User, error) {
	if actor.UUID == "" {
		return nil, domain.NewUnauthorizedError("users.emailChange.unauthorized")
	}

	// The challenge is read first only to know which address the guess counts against.
	found, err := s.challenges.Find(ctx, actor.UUID, sessionUUID, domain.SessionChallengeEmailChange)
	if err != nil {
		return nil, err
	}

	var challenge *domain.SessionChallenge
	err = guessCode(ctx, s.limiter, found.NewEmail, s.hashEmailChangeCode(sessionUUID, code), domain.ErrEmailChangeInvalidCode, func() (string, error) {
		attempted, err := s.challenges.Attempt(ctx, actor.UUID, sessionUUID, domain.SessionChallengeEmailChange, domain.EmailChangeMaxAttempts)
		if err != nil {
			return "", err
		}
		if attempted.NewEmail != found.NewEmail {
			return "", domain.ErrEmailChangeNoChallenge
		}
		challenge = attempted
		return attempted.CodeHash, nil
	})
	if err != nil {
		return nil, err
	}

	user, err := s.repo.FindByUUID(ctx, actor.UUID)
	if err != nil {
		return nil, err
	}

	// The challenge is bound to the email version it was requested for: once
	// the email changes (even back to the same value), it stops working.
	if user.EmailVersion != challenge.EmailVersion {
		return nil, domain.NewUnauthorizedError("users.emailChange.staleToken")
	}

	if isEmailChangeLocked(user) {
		return nil, domain.NewConflictError("users.emailChange.locked")
	}

	now := time.Now()
	var updated *domain.User
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		updated, err = s.repo.UpdateEmail(ctx, user.UUID, challenge.NewEmail, challenge.EmailVersion, &now)
		if err != nil {
			return err
		}
		if err := ensureEmailNotReserved(ctx, s.repo, challenge.NewEmail); err != nil {
			return err
		}
		return s.sessionsRepo.DeleteAllByUser(ctx, user.UUID)
	})
	if err != nil {
		return nil, err
	}

	notice := domain.EmailChangeRevert{
		UserUUID:  updated.UUID,
		OldEmail:  user.Email,
		NewEmail:  updated.Email,
		Version:   updated.EmailVersion,
		ChangedAt: updated.EmailChangedAt,
	}
	if err := s.emailVerification.SendEmailChangedNotice(ctx, notice); err != nil {
		slog.ErrorContext(ctx, "email changed notice failed", "error", err, "user_uuid", updated.UUID)
	}

	return updated, nil
}

// The revert token is single use because the revert bumps the version, and the
// email change lock guarantees no other change happened since the token was issued.
func (s *emailChangeService) RevertEmailChange(ctx context.Context, token string) (*domain.User, error) {
	revert, err := s.emailVerification.VerifyEmailChangeRevertToken(ctx, token)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.FindByUUID(ctx, revert.UserUUID)
	if err != nil {
		return nil, err
	}

	if user.Email != revert.NewEmail || user.EmailVersion != revert.Version {
		return nil, domain.NewUnauthorizedError("users.emailChange.staleToken")
	}

	var restored *domain.User
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		restored, err = s.repo.UpdateEmail(ctx, user.UUID, revert.OldEmail, revert.Version, nil)
		if err != nil {
			return err
		}
		if err := s.sessionsRepo.DeleteAllByUser(ctx, user.UUID); err != nil {
			return err
		}
		return s.authRepo.DeleteOAuthProvidersCreatedSince(ctx, user.UUID, time.Unix(revert.ChangedAt, 0))
	})
	if err != nil {
		return nil, err
	}

	return restored, nil
}

func (s *emailChangeService) hashEmailChangeCode(sessionUUID string, code string) string {
	return hashOTP(s.hmacKey, "email-change:"+sessionUUID, code)
}
