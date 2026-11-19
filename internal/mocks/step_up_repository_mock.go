package mocks

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type StepUpRepositoryMock struct {
	mock.Mock
}

var _ domain.StepUpRepository = (*StepUpRepositoryMock)(nil)

func (m *StepUpRepositoryMock) Upsert(ctx context.Context, challenge domain.StepUpChallenge, cooldown time.Duration) (*domain.StepUpChallenge, error) {
	args := m.Called(challenge, cooldown)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.StepUpChallenge), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *StepUpRepositoryMock) Attempt(ctx context.Context, userUUID string, sessionUUID string, maxAttempts int) (*domain.StepUpChallenge, error) {
	args := m.Called(userUUID, sessionUUID, maxAttempts)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.StepUpChallenge), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *StepUpRepositoryMock) Delete(ctx context.Context, sessionUUID string) error {
	args := m.Called(sessionUUID)
	return args.Error(0)
}
