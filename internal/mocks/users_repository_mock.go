package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type UsersRepositoryMock struct {
	mock.Mock
}

var _ domain.UsersRepository = (*UsersRepositoryMock)(nil)

func (m *UsersRepositoryMock) FindByUUID(uuid string) (*domain.User, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) Create(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *UsersRepositoryMock) Update(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *UsersRepositoryMock) Delete(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

