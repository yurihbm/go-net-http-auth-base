package services

import (
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

func (s *usersService) GetByEmail(email string) (*domain.User, error) {
	return s.repo.FindByEmail(email)
}

func (s *usersService) Create(dto domain.CreateUserDTO) (*domain.User, error) {
	user := domain.User{
		Name:  dto.Name,
		Email: dto.Email,
	}

	if dto.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, domain.NewInternalServerError("users.create.passwordHashingFailed")
		}
		user.PasswordHash = string(hash)
	}

	return s.repo.Create(user)
}

func (s *usersService) Update(uuid string, dto domain.UserUpdateDTO) error {
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

	return s.repo.Update(*user)
}

func (s *usersService) Delete(uuid string) error {
	return s.repo.Delete(uuid)
}
