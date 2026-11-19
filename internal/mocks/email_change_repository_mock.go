package mocks

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type EmailChangeRepositoryMock struct {
	mock.Mock
}

var _ domain.EmailChangeRepository = (*EmailChangeRepositoryMock)(nil)

func (m *EmailChangeRepositoryMock) Upsert(ctx context.Context, challenge domain.EmailChangeChallenge, cooldown time.Duration) (*domain.EmailChangeChallenge, error) {
	args := m.Called(challenge, cooldown)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.EmailChangeChallenge), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *EmailChangeRepositoryMock) Attempt(ctx context.Context, userUUID string, sessionUUID string, maxAttempts int) (*domain.EmailChangeChallenge, error) {
	args := m.Called(userUUID, sessionUUID, maxAttempts)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.EmailChangeChallenge), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *EmailChangeRepositoryMock) Delete(ctx context.Context, sessionUUID string) error {
	args := m.Called(sessionUUID)
	return args.Error(0)
}
