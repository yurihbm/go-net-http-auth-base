package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type EmailChangeServiceMock struct {
	mock.Mock
}

var _ domain.EmailChangeService = (*EmailChangeServiceMock)(nil)

func (m *EmailChangeServiceMock) RequestEmailChange(ctx context.Context, actor domain.Actor, sessionUUID string, email string) error {
	args := m.Called(actor, sessionUUID, email)
	return args.Error(0)
}

func (m *EmailChangeServiceMock) ConfirmEmailChange(ctx context.Context, actor domain.Actor, sessionUUID string, code string) (*domain.User, error) {
	args := m.Called(actor, sessionUUID, code)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *EmailChangeServiceMock) RevertEmailChange(ctx context.Context, token string) (*domain.User, error) {
	args := m.Called(token)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.User), args.Error(1)
	}
	return nil, args.Error(1)
}
