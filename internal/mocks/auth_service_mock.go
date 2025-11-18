package mocks

import (
	"context"
	"errors"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type AuthServiceMock struct {
	mock.Mock
}

var _ domain.AuthService = (*AuthServiceMock)(nil)

var errNotImplemented = errors.New("not implemented")

func (m *AuthServiceMock) CredentialsLogin(dto domain.CredentialsLoginDTO) (domain.AuthTokens, error) {
	args := m.Called(dto)
	if tokens, ok := args.Get(0).(domain.AuthTokens); ok {
		return tokens, args.Error(1)
	}
	return domain.AuthTokens{}, errNotImplemented
}

func (m *AuthServiceMock) RefreshToken(dto domain.RefreshTokenDTO) (domain.AuthTokens, error) {
	args := m.Called(dto)
	if tokens, ok := args.Get(0).(domain.AuthTokens); ok {
		return tokens, args.Error(1)
	}
	return domain.AuthTokens{}, errNotImplemented
}

func (m *AuthServiceMock) VerifyToken(dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.VerifiedTokenData), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AuthServiceMock) GenerateToken(dto domain.GenerateTokenDTO) (string, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.String(0), args.Error(1)
	}
	return "", errNotImplemented
}

func (m *AuthServiceMock) AddUserOAuthProvider(dto domain.AddUserOAuthProviderDTO) (*domain.UserOAuthProvider, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UserOAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AuthServiceMock) GetUserOAuthProvider(dto domain.GetUserOAuthProviderDTO) (*domain.UserOAuthProvider, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.UserOAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AuthServiceMock) RemoveUserOAuthProvider(dto domain.RemoveUserOAuthProviderDTO) error {
	args := m.Called(dto)
	return args.Error(0)
}

func (m *AuthServiceMock) GetUserOAuthProvidersByUserUUID(userUUID string) ([]domain.UserOAuthProvider, error) {
	args := m.Called(userUUID)
	if args.Get(0) != nil {
		return args.Get(0).([]domain.UserOAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *AuthServiceMock) GetOAuthProviderAuthURL(providerName domain.OAuthProviderName, state string) (string, error) {
	args := m.Called(providerName, state)
	if args.Get(0) != nil {
		return args.String(0), args.Error(1)
	}
	return "", errNotImplemented
}

func (m *AuthServiceMock) GetOAuthProviderUserInfo(ctx context.Context, providerName domain.OAuthProviderName, code string) (*domain.OAuthProviderUserInfo, error) {
	args := m.Called(ctx, providerName, code)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.OAuthProviderUserInfo), args.Error(1)
	}
	return nil, args.Error(1)
}
