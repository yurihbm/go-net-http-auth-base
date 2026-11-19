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

func (m *EmailVerificationServiceMock) SendSignupCode(ctx context.Context, email string, code string) error {
	args := m.Called(email, code)
	return args.Error(0)
}

func (m *EmailVerificationServiceMock) SendEmailChangeEmail(ctx context.Context, user *domain.User, newEmail string) error {
	args := m.Called(user, newEmail)
	return args.Error(0)
}

func (m *EmailVerificationServiceMock) VerifyEmailChangeToken(ctx context.Context, token string) (*domain.EmailChange, error) {
	args := m.Called(token)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.EmailChange), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *EmailVerificationServiceMock) SendEmailChangedNotice(ctx context.Context, revert domain.EmailChangeRevert) error {
	args := m.Called(revert)
	return args.Error(0)
}

func (m *EmailVerificationServiceMock) VerifyEmailChangeRevertToken(ctx context.Context, token string) (*domain.EmailChangeRevert, error) {
	args := m.Called(token)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.EmailChangeRevert), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *EmailVerificationServiceMock) SendStepUpCode(ctx context.Context, email string, code string) error {
	args := m.Called(email, code)
	return args.Error(0)
}
