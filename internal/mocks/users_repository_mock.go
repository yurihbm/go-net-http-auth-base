package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type UsersRepositoryMock struct {
	mock.Mock
}

var _ domain.UsersRepository = (*UsersRepositoryMock)(nil)

func (m *UsersRepositoryMock) FindByUUID(ctx context.Context, uuid string) (*domain.User, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) Create(ctx context.Context, user domain.User) (*domain.User, error) {
	args := m.Called(user)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) Update(ctx context.Context, user domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *UsersRepositoryMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}
