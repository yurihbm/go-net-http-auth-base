package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type StepUpServiceMock struct {
	mock.Mock
}

var _ domain.StepUpService = (*StepUpServiceMock)(nil)

func (m *StepUpServiceMock) RequestCode(ctx context.Context, userUUID string, sessionUUID string) error {
	args := m.Called(userUUID, sessionUUID)
	return args.Error(0)
}

func (m *StepUpServiceMock) VerifyCode(ctx context.Context, userUUID string, sessionUUID string, code string) (int64, error) {
	args := m.Called(userUUID, sessionUUID, code)
	return args.Get(0).(int64), args.Error(1)
}

func (m *StepUpServiceMock) IsElevated(ctx context.Context, userUUID string, sessionUUID string) (bool, error) {
	args := m.Called(userUUID, sessionUUID)
	return args.Bool(0), args.Error(1)
}
