package providers_test

import (
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
)

func TestNewOAuthProviderRegistry(t *testing.T) {
	t.Run("success with all providers", func(t *testing.T) {
		googleMock := new(mocks.OAuthProviderMock)
		microsoftMock := new(mocks.OAuthProviderMock)
		githubMock := new(mocks.OAuthProviderMock)

		providersMap := map[domain.OAuthProviderName]domain.OAuthProvider{
			domain.OAuthProviderGoogle:    googleMock,
			domain.OAuthProviderMicrosoft: microsoftMock,
			domain.OAuthProviderGitHub:    githubMock,
		}

		registry, err := providers.NewOAuthProviderRegistry(providersMap)

		assert.NoError(t, err)
		assert.NotNil(t, registry)
	})

	t.Run("failure when provider is nil", func(t *testing.T) {
		providersMap := map[domain.OAuthProviderName]domain.OAuthProvider{
			domain.OAuthProviderGoogle:    new(mocks.OAuthProviderMock),
			domain.OAuthProviderMicrosoft: nil,
			domain.OAuthProviderGitHub:    new(mocks.OAuthProviderMock),
		}

		registry, err := providers.NewOAuthProviderRegistry(providersMap)

		assert.Error(t, err)
		assert.Nil(t, registry)
		assert.Contains(t, err.Error(), "configured but is nil")
	})

	t.Run("failure when provider is missing", func(t *testing.T) {
		providersMap := map[domain.OAuthProviderName]domain.OAuthProvider{
			domain.OAuthProviderGoogle: new(mocks.OAuthProviderMock),
		}

		registry, err := providers.NewOAuthProviderRegistry(providersMap)

		assert.Error(t, err)
		assert.Nil(t, registry)
		assert.Contains(t, err.Error(), "not configured")
	})
}

func TestOAuthProviderRegistry_Get(t *testing.T) {
	googleMock := new(mocks.OAuthProviderMock)
	microsoftMock := new(mocks.OAuthProviderMock)
	githubMock := new(mocks.OAuthProviderMock)

	providersMap := map[domain.OAuthProviderName]domain.OAuthProvider{
		domain.OAuthProviderGoogle:    googleMock,
		domain.OAuthProviderMicrosoft: microsoftMock,
		domain.OAuthProviderGitHub:    githubMock,
	}

	registry, _ := providers.NewOAuthProviderRegistry(providersMap)

	t.Run("success with valid provider", func(t *testing.T) {
		provider, err := registry.Get(domain.OAuthProviderGoogle)

		assert.NoError(t, err)
		assert.Equal(t, googleMock, provider)
	})

	t.Run("error with invalid provider name", func(t *testing.T) {
		provider, err := registry.Get(domain.OAuthProviderName("invalid"))

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "invalid OAuth provider name")
	})

	t.Run("error with unconfigured provider", func(t *testing.T) {
		provider, err := registry.Get(domain.OAuthProviderName("linkedin"))

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "invalid OAuth provider name")
	})

	t.Run("returns all valid providers", func(t *testing.T) {
		result, err := registry.Get(domain.OAuthProviderMicrosoft)
		assert.NoError(t, err)
		assert.Equal(t, microsoftMock, result)

		result, err = registry.Get(domain.OAuthProviderGitHub)
		assert.NoError(t, err)
		assert.Equal(t, githubMock, result)
	})
}

func TestOAuthProviderRegistry_GetAll(t *testing.T) {
	t.Run("returns all configured providers", func(t *testing.T) {
		googleMock := new(mocks.OAuthProviderMock)
		microsoftMock := new(mocks.OAuthProviderMock)
		githubMock := new(mocks.OAuthProviderMock)

		providersMap := map[domain.OAuthProviderName]domain.OAuthProvider{
			domain.OAuthProviderGoogle:    googleMock,
			domain.OAuthProviderMicrosoft: microsoftMock,
			domain.OAuthProviderGitHub:    githubMock,
		}

		registry, _ := providers.NewOAuthProviderRegistry(providersMap)

		result := registry.GetAll()

		assert.Equal(t, len(providersMap), len(result))
		assert.Equal(t, googleMock, result[domain.OAuthProviderGoogle])
		assert.Equal(t, microsoftMock, result[domain.OAuthProviderMicrosoft])
		assert.Equal(t, githubMock, result[domain.OAuthProviderGitHub])
	})
}

func TestOAuthProviderRegistry_IsConfigured(t *testing.T) {
	googleMock := new(mocks.OAuthProviderMock)
	microsoftMock := new(mocks.OAuthProviderMock)
	githubMock := new(mocks.OAuthProviderMock)

	providersMap := map[domain.OAuthProviderName]domain.OAuthProvider{
		domain.OAuthProviderGoogle:    googleMock,
		domain.OAuthProviderMicrosoft: microsoftMock,
		domain.OAuthProviderGitHub:    githubMock,
	}

	registry, _ := providers.NewOAuthProviderRegistry(providersMap)

	t.Run("returns true for configured provider", func(t *testing.T) {
		result := registry.IsConfigured(domain.OAuthProviderGoogle)

		assert.True(t, result)
	})

	t.Run("returns false for invalid provider name", func(t *testing.T) {
		result := registry.IsConfigured(domain.OAuthProviderName("invalid"))

		assert.False(t, result)
	})

	t.Run("returns false for unconfigured provider", func(t *testing.T) {
		result := registry.IsConfigured(domain.OAuthProviderName("linkedin"))

		assert.False(t, result)
	})

	t.Run("checks all configured providers", func(t *testing.T) {
		assert.True(t, registry.IsConfigured(domain.OAuthProviderGoogle))
		assert.True(t, registry.IsConfigured(domain.OAuthProviderMicrosoft))
		assert.True(t, registry.IsConfigured(domain.OAuthProviderGitHub))
	})
}
