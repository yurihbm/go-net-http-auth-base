package services

import (
	"context"
	"errors"
	"log/slog"

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
		slog.Error("verification email failed", "error", err, "user_uuid", created.UUID)
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

func (s *usersService) Update(ctx context.Context, actor domain.Actor, uuid string, dto domain.UserUpdateDTO) error {
	if !actor.CanAccess(uuid) {
		return errForbiddenUserAccess
	}

	user, err := s.repo.FindByUUID(ctx, uuid)
	if err != nil {
		return err
	}

	if dto.Name != nil {
		user.Name = *dto.Name
	}
	if dto.Email != nil {
		user.Email = normalizeEmail(*dto.Email)
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

func (s *usersService) Delete(ctx context.Context, actor domain.Actor, uuid string) error {
	if !actor.CanAccess(uuid) {
		return errForbiddenUserAccess
	}
	return s.repo.Delete(ctx, uuid)
}
