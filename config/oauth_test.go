package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/config"
)

func TestNewMicrosoftOAuthConfig(t *testing.T) {
	cfg := config.NewMicrosoftOAuthConfig(config.OAuthProviderCredentials{ClientID: "id", ClientSecret: "secret"}, "https://api.example.com")

	assert.Equal(t, []string{"openid", "email", "profile"}, cfg.Scopes)
	assert.Equal(t, "https://api.example.com/auth/microsoft/callback", cfg.RedirectURL)
}
