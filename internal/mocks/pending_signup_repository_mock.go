package mocks

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type PendingSignupRepositoryMock struct {
	mock.Mock
}

var _ domain.PendingSignupRepository = (*PendingSignupRepositoryMock)(nil)

func (m *PendingSignupRepositoryMock) Create(ctx context.Context, pending domain.PendingSignup) (*domain.PendingSignup, error) {
	args := m.Called(pending)
	return pendingSignupResult(args)
}

func (m *PendingSignupRepositoryMock) FindByUUID(ctx context.Context, uuid string) (*domain.PendingSignup, error) {
	args := m.Called(uuid)
	return pendingSignupResult(args)
}

func (m *PendingSignupRepositoryMock) Attempt(ctx context.Context, uuid string, maxAttempts int) (*domain.PendingSignup, error) {
	args := m.Called(uuid, maxAttempts)
	return pendingSignupResult(args)
}

func (m *PendingSignupRepositoryMock) Consume(ctx context.Context, uuid string, codeHash string) (*domain.PendingSignup, error) {
	args := m.Called(uuid, codeHash)
	return pendingSignupResult(args)
}

func (m *PendingSignupRepositoryMock) Resend(ctx context.Context, uuid string, codeHash string, codeTTL time.Duration, cooldown time.Duration) (*domain.PendingSignup, error) {
	args := m.Called(uuid, codeHash, codeTTL, cooldown)
	return pendingSignupResult(args)
}

func (m *PendingSignupRepositoryMock) Delete(ctx context.Context, uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func pendingSignupResult(args mock.Arguments) (*domain.PendingSignup, error) {
	if args.Get(0) != nil {
		return args.Get(0).(*domain.PendingSignup), args.Error(1)
	}
	return nil, args.Error(1)
}
