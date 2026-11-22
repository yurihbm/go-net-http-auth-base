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

func (m *EmailVerificationServiceMock) SendOAuthSignupCode(ctx context.Context, email string, code string, provider domain.OAuthProviderName) error {
	args := m.Called(email, code, provider)
	return args.Error(0)
}

func (m *EmailVerificationServiceMock) SendEmailChangeCode(ctx context.Context, newEmail string, code string) error {
	args := m.Called(newEmail, code)
	return args.Error(0)
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

func (m *EmailVerificationServiceMock) SendOAuthLinkedNotice(ctx context.Context, to string, revert domain.OAuthLinkRevert) error {
	args := m.Called(to, revert)
	return args.Error(0)
}

func (m *EmailVerificationServiceMock) VerifyOAuthLinkRevertToken(ctx context.Context, token string) (*domain.OAuthLinkRevert, error) {
	args := m.Called(token)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.OAuthLinkRevert), args.Error(1)
	}
	return nil, args.Error(1)
}
