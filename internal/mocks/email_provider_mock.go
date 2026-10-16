package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type EmailProviderMock struct {
	mock.Mock
}

var _ domain.EmailProvider = (*EmailProviderMock)(nil)

func (m *EmailProviderMock) Send(ctx context.Context, msg domain.EmailMessage) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}
