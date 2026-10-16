package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type TokenVerifierMock struct {
	mock.Mock
}

var _ domain.TokenVerifier = (*TokenVerifierMock)(nil)

func (m *TokenVerifierMock) VerifyToken(ctx context.Context, dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.VerifiedTokenData), args.Error(1)
	}
	return nil, args.Error(1)
}
