package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type OAuthProviderMock struct {
	mock.Mock
}

var _ domain.OAuthProvider = (*OAuthProviderMock)(nil)

func (m *OAuthProviderMock) GetAuthURL(_ context.Context, state string, codeVerifier string) string {
	args := m.Called(state, codeVerifier)
	return args.String(0)
}

func (m *OAuthProviderMock) GetUserInfo(ctx context.Context, code string, codeVerifier string) (*domain.OAuthProviderUserInfo, error) {
	args := m.Called(ctx, code, codeVerifier)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.OAuthProviderUserInfo), args.Error(1)
	}
	return nil, args.Error(1)
}
