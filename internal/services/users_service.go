package services

import (
	"errors"
	"go-net-http-auth-base/internal/domain"

	"golang.org/x/crypto/bcrypt"
)

type usersService struct {
	repo domain.UsersRepository
}

func NewUserService(repo domain.UsersRepository) domain.UsersService {
	return &usersService{repo: repo}
}

func (s *usersService) GetByUUID(uuid string) (*domain.User, error) {
	return s.repo.FindByUUID(uuid)
}

func (s *usersService) Create(dto *domain.CreateUserDTO) (*domain.User, error) {
	user := &domain.User{
		Name:       dto.Name,
		Email:      dto.Email,
		AuthMethod: dto.AuthMethod,
	}

	if dto.AuthMethod == domain.AuthMethodEmail {
		if dto.Password == nil {
			return nil, errors.New("user.create.password_required")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*dto.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		user.PasswordHash = string(hash)
	}

	err := s.repo.Create(user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *usersService) Update(uuid string, dto *domain.UserUpdateDTO) error {
	user, err := s.repo.FindByUUID(uuid)
	if err != nil {
		return err
	}

	if dto.Name != nil {
		user.Name = *dto.Name
	}
	if dto.Email != nil {
		user.Email = *dto.Email
	}

	if err = s.repo.Update(user); err != nil {
		return err
	}
	return nil
}

func (s *usersService) Delete(uuid string) error {
	return s.repo.Delete(uuid)
}
