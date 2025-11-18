package providers

import (
	"fmt"

	"go-net-http-auth-base/internal/domain"
)

type oauthProviderRegistry struct {
	providers map[domain.OAuthProviderName]domain.OAuthProvider
}

var _ domain.OAuthProviderRegistry = (*oauthProviderRegistry)(nil)

func NewOAuthProviderRegistry(providers map[domain.OAuthProviderName]domain.OAuthProvider) (domain.OAuthProviderRegistry, error) {
	registry := &oauthProviderRegistry{
		providers: providers,
	}

	if err := registry.validate(); err != nil {
		return nil, err
	}

	return registry, nil
}

func (r *oauthProviderRegistry) Get(name domain.OAuthProviderName) (domain.OAuthProvider, error) {
	if !name.IsValid() {
		return nil, fmt.Errorf("invalid OAuth provider name: %s", name)
	}

	provider, exists := r.providers[name]
	if !exists {
		return nil, fmt.Errorf("OAuth provider '%s' is not configured", name)
	}

	if provider == nil {
		return nil, fmt.Errorf("OAuth provider '%s' is configured but is nil", name)
	}

	return provider, nil
}

func (r *oauthProviderRegistry) GetAll() map[domain.OAuthProviderName]domain.OAuthProvider {
	return r.providers
}

func (r *oauthProviderRegistry) IsConfigured(name domain.OAuthProviderName) bool {
	provider, exists := r.providers[name]
	return exists && provider != nil
}

func (r *oauthProviderRegistry) validate() error {
	validProviders := []domain.OAuthProviderName{
		domain.OAuthProviderGoogle,
		domain.OAuthProviderMicrosoft,
		domain.OAuthProviderGitHub,
	}

	for _, providerName := range validProviders {
		provider, exists := r.providers[providerName]
		if !exists {
			return fmt.Errorf("required OAuth provider '%s' is not configured", providerName)
		}

		if provider == nil {
			return fmt.Errorf("OAuth provider '%s' is configured but is nil", providerName)
		}
	}

	return nil
}
