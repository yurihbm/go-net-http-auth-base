package mocks

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type SessionsRepositoryMock struct {
	mock.Mock
}

var _ domain.SessionsRepository = (*SessionsRepositoryMock)(nil)

func (m *SessionsRepositoryMock) Create(ctx context.Context, session domain.UserSession) (*domain.UserSession, error) {
	args := m.Called(session)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UserSession), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *SessionsRepositoryMock) FindByUUID(ctx context.Context, userUUID string, sessionUUID string) (*domain.UserSession, error) {
	args := m.Called(userUUID, sessionUUID)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UserSession), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *SessionsRepositoryMock) RotateJTI(ctx context.Context, userUUID string, sessionUUID string, currentJTI string, nextJTI string) error {
	args := m.Called(userUUID, sessionUUID, currentJTI, nextJTI)
	return args.Error(0)
}

func (m *SessionsRepositoryMock) Delete(ctx context.Context, userUUID string, sessionUUID string) error {
	args := m.Called(userUUID, sessionUUID)
	return args.Error(0)
}

func (m *SessionsRepositoryMock) DeleteExpiredByUser(ctx context.Context, userUUID string, idleTimeout time.Duration) error {
	args := m.Called(userUUID, idleTimeout)
	return args.Error(0)
}

func (m *SessionsRepositoryMock) DeleteOldestBeyond(ctx context.Context, userUUID string, keep int) error {
	args := m.Called(userUUID, keep)
	return args.Error(0)
}
