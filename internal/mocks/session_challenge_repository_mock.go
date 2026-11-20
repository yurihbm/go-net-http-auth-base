package mocks

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type SessionChallengeRepositoryMock struct {
	mock.Mock
}

var _ domain.SessionChallengeRepository = (*SessionChallengeRepositoryMock)(nil)

func (m *SessionChallengeRepositoryMock) Upsert(ctx context.Context, challenge domain.SessionChallenge, cooldown time.Duration) error {
	args := m.Called(challenge, cooldown)
	return args.Error(0)
}

func (m *SessionChallengeRepositoryMock) Find(ctx context.Context, userUUID string, sessionUUID string, purpose domain.SessionChallengePurpose) (*domain.SessionChallenge, error) {
	args := m.Called(userUUID, sessionUUID, purpose)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.SessionChallenge), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *SessionChallengeRepositoryMock) Attempt(ctx context.Context, userUUID string, sessionUUID string, purpose domain.SessionChallengePurpose, maxAttempts int) (*domain.SessionChallenge, error) {
	args := m.Called(userUUID, sessionUUID, purpose, maxAttempts)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.SessionChallenge), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *SessionChallengeRepositoryMock) Delete(ctx context.Context, sessionUUID string, purpose domain.SessionChallengePurpose) error {
	args := m.Called(sessionUUID, purpose)
	return args.Error(0)
}
