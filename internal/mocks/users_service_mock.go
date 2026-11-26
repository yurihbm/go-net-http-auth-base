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

func (m *UsersServiceMock) GetByUUID(ctx context.Context, actor domain.Actor, uuid string) (*domain.User, error) {
	args := m.Called(actor, uuid)
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

func (m *UsersServiceMock) PromoteToAdmin(ctx context.Context, email string) (*domain.User, bool, error) {
	args := m.Called(email)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Bool(1), args.Error(2)
	}
	return nil, args.Bool(1), args.Error(2)
}

func (m *UsersServiceMock) Create(ctx context.Context, dto domain.NewUserDTO) (*domain.User, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) CreateOAuth(ctx context.Context, dto domain.CreateOAuthUserDTO) (*domain.User, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) Update(ctx context.Context, actor domain.Actor, uuid string, dto domain.UserUpdateDTO) (*domain.User, error) {
	args := m.Called(actor, uuid, dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersServiceMock) Delete(ctx context.Context, actor domain.Actor, uuid string) error {
	args := m.Called(actor, uuid)
	return args.Error(0)
}

func (m *UsersServiceMock) List(ctx context.Context, dto domain.ListUsersDTO) (*domain.UsersPage, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UsersPage), args.Error(1)
	}
	return nil, args.Error(1)
}
