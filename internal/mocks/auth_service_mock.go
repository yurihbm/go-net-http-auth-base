package mocks

import (
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

func (m *AuthServiceMock) VerifyToken(dto domain.VerifyTokenDTO) (string, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.String(0), args.Error(1)
	}
	return "", errNotImplemented
}

func (m *AuthServiceMock) GenerateToken(dto domain.GenerateTokenDTO) (string, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.String(0), args.Error(1)
	}
	return "", errNotImplemented
}
