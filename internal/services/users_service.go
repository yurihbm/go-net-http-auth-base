package services

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go-net-http-auth-base/internal/domain"

	"golang.org/x/crypto/bcrypt"
)

var errForbiddenUserAccess = domain.NewForbiddenError("users.forbidden")

type usersService struct {
	repo              domain.UsersRepository
	emailVerification domain.EmailVerificationService
}

func NewUserService(repo domain.UsersRepository, emailVerification domain.EmailVerificationService) domain.UsersService {
	return &usersService{repo: repo, emailVerification: emailVerification}
}

func (s *usersService) GetByUUID(ctx context.Context, actor domain.Actor, uuid string) (*domain.User, error) {
	if !actor.CanAccess(uuid) {
		return nil, errForbiddenUserAccess
	}
	return s.repo.FindByUUID(ctx, uuid)
}

func (s *usersService) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.repo.FindByEmail(ctx, normalizeEmail(email))
}

func (s *usersService) Create(ctx context.Context, dto domain.CreateUserDTO) (*domain.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, domain.NewInternalServerError("users.create.passwordHashingFailed", err)
	}
	user := domain.User{
		Name:         dto.Name,
		Email:        normalizeEmail(dto.Email),
		PasswordHash: string(hash),
		Role:         domain.RoleUser,
	}
	created, err := s.repo.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	if err := s.emailVerification.SendVerificationEmail(ctx, created); err != nil {
		slog.ErrorContext(ctx, "verification email failed", "error", err, "user_uuid", created.UUID)
	}

	return created, nil
}

func (s *usersService) CreateOAuth(ctx context.Context, dto domain.CreateOAuthUserDTO) (*domain.User, error) {
	user := domain.User{
		Name:          dto.Name,
		Email:         normalizeEmail(dto.Email),
		Role:          domain.RoleUser,
		EmailVerified: dto.EmailVerified,
	}
	return s.repo.Create(ctx, user)
}

func (s *usersService) Update(ctx context.Context, actor domain.Actor, uuid string, dto domain.UserUpdateDTO) (*domain.User, error) {
	if !actor.CanAccess(uuid) {
		return nil, errForbiddenUserAccess
	}

	user, err := s.repo.FindByUUID(ctx, uuid)
	if err != nil {
		return nil, err
	}

	if dto.Name != nil {
		user.Name = *dto.Name
	}

	return s.repo.Update(ctx, *user)
}

func (s *usersService) VerifyEmail(ctx context.Context, token string) error {
	userUUID, err := s.emailVerification.VerifyVerificationToken(ctx, token)
	if err != nil {
		return err
	}

	user, err := s.repo.FindByUUID(ctx, userUUID)
	if err != nil {
		return err
	}

	if user.EmailVerified {
		return nil
	}

	return s.repo.MarkEmailVerified(ctx, user.UUID)
}

func (s *usersService) ResendVerification(ctx context.Context, email string) error {
	user, err := s.GetByEmail(ctx, email)
	if err != nil {
		var notFoundErr *domain.NotFoundError
		if errors.As(err, &notFoundErr) {
			return nil
		}
		return err
	}

	if user.EmailVerified {
		return nil
	}

	return s.emailVerification.SendVerificationEmail(ctx, user)
}

func (s *usersService) RequestEmailChange(ctx context.Context, actor domain.Actor, email string) error {
	if actor.UUID == "" {
		return domain.NewUnauthorizedError("users.emailChange.unauthorized")
	}

	user, err := s.repo.FindByUUID(ctx, actor.UUID)
	if err != nil {
		return err
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

	return s.emailVerification.SendEmailChangeEmail(ctx, user, newEmail)
}

func (s *usersService) ConfirmEmailChange(ctx context.Context, token string) (*domain.User, error) {
	change, err := s.emailVerification.VerifyEmailChangeToken(ctx, token)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.FindByUUID(ctx, change.UserUUID)
	if err != nil {
		return nil, err
	}

	// The token is bound to the email it was issued for: once the email changes,
	// this token and any other pending one stop working.
	if user.Email != change.CurrentEmail {
		return nil, domain.NewUnauthorizedError("users.emailChange.staleToken")
	}

	now := time.Now()
	updated, err := s.repo.UpdateEmail(ctx, user.UUID, change.NewEmail, user.EmailVersion, &now)
	if err != nil {
		return nil, err
	}

	if err := s.emailVerification.SendEmailChangedNotice(ctx, change.CurrentEmail, updated.Email); err != nil {
		slog.ErrorContext(ctx, "email changed notice failed", "error", err, "user_uuid", updated.UUID)
	}

	return updated, nil
}

func (s *usersService) Delete(ctx context.Context, actor domain.Actor, uuid string) error {
	if !actor.CanAccess(uuid) {
		return errForbiddenUserAccess
	}
	return s.repo.Delete(ctx, uuid)
}
