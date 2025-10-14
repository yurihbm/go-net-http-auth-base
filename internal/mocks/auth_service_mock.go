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

func (m *AuthServiceMock) Authenticate(dto domain.AuthDTO) (string, string, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.String(0), args.String(1), args.Error(2)
	}
	return "", "", errNotImplemented
}

func (m *AuthServiceMock) VerifyToken(tokenString string) (string, error) {
	args := m.Called(tokenString)
	if args.Get(0) != nil {
		return args.String(0), args.Error(1)
	}
	return "", errNotImplemented
}

func (m *AuthServiceMock) RefreshToken(refreshToken string) (string, string, error) {
	args := m.Called(refreshToken)
	if args.Get(0) != nil {
		return args.String(0), args.String(1), args.Error(2)
	}
	return "", "", errNotImplemented
}
