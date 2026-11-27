package mocks

import (
	"context"
	"time"

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

func (m *UsersRepositoryMock) Update(ctx context.Context, user domain.User) (*domain.User, error) {
	args := m.Called(user)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) UpdateEmail(ctx context.Context, uuid string, email string, expectedVersion int, changedAt *time.Time) (*domain.User, error) {
	args := m.Called(uuid, email, expectedVersion, changedAt)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) UpdateRole(ctx context.Context, uuid string, role domain.UserRole) (*domain.User, error) {
	args := m.Called(uuid, role)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) IsEmailReserved(ctx context.Context, email string) (bool, error) {
	args := m.Called(email)
	return args.Bool(0), args.Error(1)
}

func (m *UsersRepositoryMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *UsersRepositoryMock) ReserveStepUpGuess(ctx context.Context, uuid string, window time.Duration) error {
	args := m.Called(uuid, window)
	return args.Error(0)
}

func (m *UsersRepositoryMock) RefundStepUpGuess(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *UsersRepositoryMock) UpdatePassword(ctx context.Context, uuid string, passwordHash string, expectedEmailVersion *int) (*domain.User, error) {
	args := m.Called(uuid, passwordHash, expectedEmailVersion)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *UsersRepositoryMock) List(ctx context.Context, dto domain.ListUsersDTO) ([]domain.User, int64, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).([]domain.User), args.Get(1).(int64), args.Error(2)
	}
	return nil, 0, args.Error(2)
}
