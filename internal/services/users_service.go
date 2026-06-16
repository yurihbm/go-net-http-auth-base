package services

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"golang.org/x/crypto/bcrypt"
)

type usersService struct {
	repo domain.UsersRepository
}

func NewUserService(repo domain.UsersRepository) domain.UsersService {
	return &usersService{repo: repo}
}

func (s *usersService) GetByUUID(ctx context.Context, uuid string) (*domain.User, error) {
	return s.repo.FindByUUID(ctx, uuid)
}

func (s *usersService) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.repo.FindByEmail(ctx, email)
}

func (s *usersService) Create(ctx context.Context, dto domain.CreateUserDTO) (*domain.User, error) {
	user := domain.User{
		Name:  dto.Name,
		Email: dto.Email,
		Role:  domain.RoleUser,
	}

	if dto.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, domain.NewInternalServerError("users.create.passwordHashingFailed", err)
		}
		user.PasswordHash = string(hash)
	}

	return s.repo.Create(ctx, user)
}

func (s *usersService) Update(ctx context.Context, uuid string, dto domain.UserUpdateDTO) error {
	user, err := s.repo.FindByUUID(ctx, uuid)
	if err != nil {
		return err
	}

	if dto.Name != nil {
		user.Name = *dto.Name
	}
	if dto.Email != nil {
		user.Email = *dto.Email
	}

	return s.repo.Update(ctx, *user)
}

func (s *usersService) Delete(ctx context.Context, uuid string) error {
	// TODO: Check if users is deleting itself or if this is a admin action
	return s.repo.Delete(ctx, uuid)
}
