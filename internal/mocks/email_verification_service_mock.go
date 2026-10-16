package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type EmailVerificationServiceMock struct {
	mock.Mock
}

var _ domain.EmailVerificationService = (*EmailVerificationServiceMock)(nil)

func (m *EmailVerificationServiceMock) SendVerificationEmail(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *EmailVerificationServiceMock) VerifyVerificationToken(ctx context.Context, token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}
