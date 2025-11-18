package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type OAuthProviderRegistryMock struct {
	mock.Mock
}

var _ domain.OAuthProviderRegistry = (*OAuthProviderRegistryMock)(nil)

func (m *OAuthProviderRegistryMock) Get(name domain.OAuthProviderName) (domain.OAuthProvider, error) {
	args := m.Called(name)
	if args.Get(0) != nil {
		return args.Get(0).(domain.OAuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *OAuthProviderRegistryMock) GetAll() map[domain.OAuthProviderName]domain.OAuthProvider {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(map[domain.OAuthProviderName]domain.OAuthProvider)
	}
	return nil
}

func (m *OAuthProviderRegistryMock) IsConfigured(name domain.OAuthProviderName) bool {
	args := m.Called(name)
	return args.Bool(0)
}
