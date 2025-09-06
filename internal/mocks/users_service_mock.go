package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type UsersServiceMock struct {
	mock.Mock
}

var _ domain.UsersService = (*UsersServiceMock)(nil)

func (m *UsersServiceMock) GetByUUID(uuid string) (*domain.User, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) Create(dto *domain.CreateUserDTO) (*domain.User, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) Update(uuid string, dto *domain.UserUpdateDTO) error {
	args := m.Called(uuid, dto)
	return args.Error(0)
}

func (m *UsersServiceMock) Delete(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}
