package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type AuthRepositoryMock struct {
	mock.Mock
}

var _ domain.AuthRepository = (*AuthRepositoryMock)(nil)

func (m *AuthRepositoryMock) CreateUserOAuthProvider(provider domain.UserOAuthProvider) (*domain.UserOAuthProvider, error) {
	args := m.Called(provider)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UserOAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AuthRepositoryMock) GetUserOAuthProviderByProviderAndProviderUserID(provider domain.OAuthProvider, providerUserID string) (*domain.UserOAuthProvider, error) {
	args := m.Called(provider, providerUserID)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UserOAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AuthRepositoryMock) DeleteUserOAuthProvider(uuid string) error {
	args := m.Called(uuid)
	return args.Error(0)
}

func (m *AuthRepositoryMock) ListUserOAuthProvidersByUserUUID(userUUID string) ([]domain.UserOAuthProvider, error) {
	args := m.Called(userUUID)
	if args.Get(0) != nil {
		return args.Get(0).([]domain.UserOAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}
