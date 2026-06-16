package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type UsersServiceMock struct {
	mock.Mock
}

var _ domain.UsersService = (*UsersServiceMock)(nil)

func (m *UsersServiceMock) GetByUUID(ctx context.Context, uuid string) (*domain.User, error) {
	args := m.Called(uuid)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) Create(ctx context.Context, dto domain.CreateUserDTO) (*domain.User, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) Update(ctx context.Context, uuid string, dto domain.UserUpdateDTO) error {
	args := m.Called(uuid, dto)
	return args.Error(0)
}

func (m *UsersServiceMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}
