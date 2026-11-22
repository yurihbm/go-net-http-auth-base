package services

import (
	"context"
	"errors"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type pendingSignupService struct {
	pending    domain.PendingSignupRepository
	limiter    domain.EmailSendLimiter
	users      domain.UsersRepository
	transactor domain.Transactor
	emails     domain.EmailVerificationService
	hmacKey    []byte
}

func NewPendingSignupService(
	pending domain.PendingSignupRepository,
	limiter domain.EmailSendLimiter,
	users domain.UsersRepository,
	transactor domain.Transactor,
	emails domain.EmailVerificationService,
	hmacKey []byte,
) domain.PendingSignupService {
	return &pendingSignupService{
		pending:    pending,
		limiter:    limiter,
		users:      users,
		transactor: transactor,
		emails:     emails,
		hmacKey:    hmacKey,
	}
}

func (s *pendingSignupService) StartCredentials(ctx context.Context, dto domain.CreateUserDTO) (string, error) {
	email := normalizeEmail(dto.Email)
	if err := s.ensureEmailAvailable(ctx, email); err != nil {
		return "", err
	}

	if err := s.reserveSend(ctx, email); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", domain.NewInternalServerError("users.create.passwordHashingFailed", err)
	}

	return s.start(ctx, domain.PendingSignup{
		Kind:         domain.PendingSignupKindCredentials,
		Name:         dto.Name,
		Email:        email,
		PasswordHash: string(hash),
	})
}

func (s *pendingSignupService) StartOAuth(ctx context.Context, dto domain.StartOAuthSignupDTO) (string, error) {
	email := normalizeEmail(dto.Email)
	if err := s.reserveSend(ctx, email); err != nil {
		return "", err
	}

	return s.start(ctx, domain.PendingSignup{
		Kind:           domain.PendingSignupKindOAuth,
		Name:           dto.Name,
		Email:          email,
		Provider:       dto.Provider,
		ProviderUserID: dto.ProviderUserID,
	})
}

func (s *pendingSignupService) Resend(ctx context.Context, pendingUUID string) error {
	pending, err := s.pending.FindByUUID(ctx, pendingUUID)
	if err != nil {
		return err
	}

	code, err := generateOTP()
	if err != nil {
		return domain.NewInternalServerError("auth.signup.codeGenerationFailed", err)
	}

	// The new code only replaces the old one when the address may receive another email.
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		if _, err := s.pending.Resend(ctx, pendingUUID, s.hashCode(pendingUUID, code), domain.SignupCodeTTL); err != nil {
			return err
		}
		return s.reserveSend(ctx, pending.Email)
	})
	if err != nil {
		return err
	}

	if err := s.sendCode(ctx, *pending, code); err != nil {
		return domain.NewInternalServerError("auth.signup.sendFailed", err)
	}
	return nil
}

func (s *pendingSignupService) Attempt(ctx context.Context, pendingUUID string, code string) error {
	pending, err := s.pending.FindByUUID(ctx, pendingUUID)
	if err != nil {
		return err
	}

	return guessCode(ctx, s.limiter, pending.Email, s.hashCode(pendingUUID, code), domain.ErrSignupInvalidCode, func() (string, error) {
		attempted, err := s.pending.Attempt(ctx, pendingUUID, domain.SignupMaxAttempts)
		if err != nil {
			return "", err
		}
		return attempted.CodeHash, nil
	})
}

func (s *pendingSignupService) Consume(ctx context.Context, pendingUUID string, code string) (*domain.PendingSignup, error) {
	return s.pending.Consume(ctx, pendingUUID, s.hashCode(pendingUUID, code))
}

func (s *pendingSignupService) start(ctx context.Context, pending domain.PendingSignup) (string, error) {
	pendingUUID, err := uuid.NewV7()
	if err != nil {
		return "", domain.NewInternalServerError("auth.signup.codeGenerationFailed", err)
	}
	code, err := generateOTP()
	if err != nil {
		return "", domain.NewInternalServerError("auth.signup.codeGenerationFailed", err)
	}

	now := time.Now()
	pending.UUID = pendingUUID.String()
	pending.CodeHash = s.hashCode(pending.UUID, code)
	pending.CodeExpiresAt = now.Add(domain.SignupCodeTTL).Unix()
	pending.ExpiresAt = now.Add(domain.PendingSignupTTL).Unix()

	created, err := s.pending.Create(ctx, pending)
	if err != nil {
		return "", err
	}

	err = sendOrRollback(ctx, "auth.signup.sendFailed",
		func() error { return s.sendCode(ctx, pending, code) },
		func() error { return s.pending.Delete(ctx, created.UUID) },
	)
	if err != nil {
		return "", err
	}
	return created.UUID, nil
}

func (s *pendingSignupService) sendCode(ctx context.Context, pending domain.PendingSignup, code string) error {
	if pending.Kind == domain.PendingSignupKindOAuth {
		return s.emails.SendOAuthSignupCode(ctx, pending.Email, code, pending.Provider)
	}
	return s.emails.SendSignupCode(ctx, pending.Email, code)
}

func (s *pendingSignupService) reserveSend(ctx context.Context, email string) error {
	return s.limiter.ReserveSend(ctx, email, domain.EmailSendCooldown, domain.EmailSendWindow, domain.EmailMaxSendsPerWindow)
}

func (s *pendingSignupService) ensureEmailAvailable(ctx context.Context, email string) error {
	existing, err := s.users.FindByEmail(ctx, email)
	var notFoundErr *domain.NotFoundError
	if err != nil && !errors.As(err, &notFoundErr) {
		return err
	}
	if existing != nil {
		return domain.NewConflictError("users.email.conflict")
	}

	reserved, err := s.users.IsEmailReserved(ctx, email)
	if err != nil {
		return err
	}
	if reserved {
		return domain.NewConflictError("users.email.conflict")
	}
	return nil
}

func (s *pendingSignupService) hashCode(pendingUUID string, code string) string {
	return hashOTP(s.hmacKey, "signup:"+pendingUUID, code)
}
