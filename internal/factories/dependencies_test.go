package factories

import (
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEmailProvider(t *testing.T) {
	t.Run("uses the log provider with the body outside production", func(t *testing.T) {
		provider := newEmailProvider("development", config.EmailConfig{})

		assert.Equal(t, providers.NewLogEmailProvider(true), provider)
	})

	t.Run("uses the log provider without the body in production", func(t *testing.T) {
		provider := newEmailProvider("production", config.EmailConfig{})

		assert.Equal(t, providers.NewLogEmailProvider(false), provider)
	})

	t.Run("uses the resend provider with an API key", func(t *testing.T) {
		provider := newEmailProvider("production", config.EmailConfig{ResendAPIKey: "re_key", From: "no-reply@example.com"})

		assert.IsType(t, providers.NewResendEmailProvider("re_key", "no-reply@example.com"), provider)
	})
}

func TestNewDependencies(t *testing.T) {
	deps, err := NewDependencies(nil, &config.Config{JWTSecret: "test-secret-key"})

	require.NoError(t, err)
	assert.NotNil(t, deps.UsersService)
	assert.NotNil(t, deps.AuthService)
	assert.NotNil(t, deps.PendingSignupService)
	assert.NotNil(t, deps.PasswordService)
	assert.NotNil(t, deps.AuditService)
	assert.NotNil(t, deps.FeatureFlagsService)
	assert.NotNil(t, deps.AuthMiddleware)
}
