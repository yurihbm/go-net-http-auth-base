package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type PasswordServiceMock struct {
	mock.Mock
}

var _ domain.PasswordService = (*PasswordServiceMock)(nil)

func (m *PasswordServiceMock) RequestReset(ctx context.Context, email string) (string, error) {
	args := m.Called(email)
	return args.String(0), args.Error(1)
}

func (m *PasswordServiceMock) ResetPassword(ctx context.Context, resetUUID string, dto domain.ResetPasswordDTO) (*domain.User, error) {
	args := m.Called(resetUUID, dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *PasswordServiceMock) ChangePassword(ctx context.Context, actor domain.Actor, sessionUUID string, dto domain.ChangePasswordDTO) error {
	args := m.Called(actor, sessionUUID, dto)
	return args.Error(0)
}
