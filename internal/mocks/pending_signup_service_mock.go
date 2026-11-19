package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type PendingSignupServiceMock struct {
	mock.Mock
}

var _ domain.PendingSignupService = (*PendingSignupServiceMock)(nil)

func (m *PendingSignupServiceMock) StartCredentials(ctx context.Context, dto domain.CreateUserDTO) (string, error) {
	args := m.Called(dto)
	return args.String(0), args.Error(1)
}

func (m *PendingSignupServiceMock) StartOAuth(ctx context.Context, dto domain.StartOAuthSignupDTO) (string, error) {
	args := m.Called(dto)
	return args.String(0), args.Error(1)
}

func (m *PendingSignupServiceMock) Resend(ctx context.Context, pendingUUID string) error {
	args := m.Called(pendingUUID)
	return args.Error(0)
}

func (m *PendingSignupServiceMock) Attempt(ctx context.Context, pendingUUID string, code string) error {
	args := m.Called(pendingUUID, code)
	return args.Error(0)
}

func (m *PendingSignupServiceMock) Consume(ctx context.Context, pendingUUID string, code string) (*domain.PendingSignup, error) {
	args := m.Called(pendingUUID, code)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.PendingSignup), args.Error(1)
	}
	return nil, args.Error(1)
}
