package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type PasswordResetRepositoryMock struct {
	mock.Mock
}

var _ domain.PasswordResetRepository = (*PasswordResetRepositoryMock)(nil)

func (m *PasswordResetRepositoryMock) Create(ctx context.Context, reset domain.PasswordReset) (*domain.PasswordReset, error) {
	args := m.Called(reset)
	return passwordResetResult(args)
}

func (m *PasswordResetRepositoryMock) FindByUUID(ctx context.Context, uuid string) (*domain.PasswordReset, error) {
	args := m.Called(uuid)
	return passwordResetResult(args)
}

func (m *PasswordResetRepositoryMock) Attempt(ctx context.Context, uuid string, maxAttempts int) (*domain.PasswordReset, error) {
	args := m.Called(uuid, maxAttempts)
	return passwordResetResult(args)
}

func (m *PasswordResetRepositoryMock) Consume(ctx context.Context, uuid string, codeHash string) (*domain.PasswordReset, error) {
	args := m.Called(uuid, codeHash)
	return passwordResetResult(args)
}

func (m *PasswordResetRepositoryMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *PasswordResetRepositoryMock) DeleteByUser(ctx context.Context, userUUID string) error {
	args := m.Called(userUUID)
	return args.Error(0)
}

func passwordResetResult(args mock.Arguments) (*domain.PasswordReset, error) {
	if args.Get(0) != nil {
		return args.Get(0).(*domain.PasswordReset), args.Error(1)
	}
	return nil, args.Error(1)
}
