package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type TokenServiceMock struct {
	mock.Mock
}

var _ domain.TokenService = (*TokenServiceMock)(nil)

func (m *TokenServiceMock) GenerateToken(ctx context.Context, dto domain.GenerateTokenDTO) (string, error) {
	args := m.Called(dto)
	return args.String(0), args.Error(1)
}

func (m *TokenServiceMock) VerifyToken(ctx context.Context, dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.VerifiedTokenData), args.Error(1)
	}
	return nil, args.Error(1)
}
