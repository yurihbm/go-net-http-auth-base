package mocks

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type EmailSendLimiterMock struct {
	mock.Mock
}

var _ domain.EmailSendLimiter = (*EmailSendLimiterMock)(nil)

func (m *EmailSendLimiterMock) ReserveSend(ctx context.Context, email string, cooldown time.Duration, window time.Duration, maxSends int) error {
	args := m.Called(email, cooldown, window, maxSends)
	return args.Error(0)
}

func (m *EmailSendLimiterMock) CodeFailures(ctx context.Context, email string, window time.Duration) (int, error) {
	args := m.Called(email, window)
	return args.Int(0), args.Error(1)
}

func (m *EmailSendLimiterMock) RecordCodeFailure(ctx context.Context, email string, window time.Duration) (int, error) {
	args := m.Called(email, window)
	return args.Int(0), args.Error(1)
}
