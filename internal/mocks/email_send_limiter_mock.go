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

func (m *EmailSendLimiterMock) ReserveCodeGuess(ctx context.Context, email string, window time.Duration) error {
	args := m.Called(email, window)
	return args.Error(0)
}

func (m *EmailSendLimiterMock) RefundCodeGuess(ctx context.Context, email string) error {
	args := m.Called(email)
	return args.Error(0)
}
