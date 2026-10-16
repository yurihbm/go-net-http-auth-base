package factories

import (
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEmailProvider(t *testing.T) {
	t.Run("uses the log provider without an API key", func(t *testing.T) {
		provider := newEmailProvider(config.EmailConfig{})

		assert.Equal(t, providers.NewLogEmailProvider(), provider)
	})

	t.Run("uses the resend provider with an API key", func(t *testing.T) {
		provider := newEmailProvider(config.EmailConfig{ResendAPIKey: "re_key", From: "no-reply@example.com"})

		assert.Equal(t, providers.NewResendEmailProvider("re_key", "no-reply@example.com"), provider)
	})
}

func TestNewDependencies(t *testing.T) {
	deps, err := NewDependencies(nil, &config.Config{
		JWTSecret: "test-secret-key",
		Email:     config.EmailConfig{VerificationURL: "https://app.test/verify-email"},
	})

	require.NoError(t, err)
	assert.NotNil(t, deps.UsersService)
	assert.NotNil(t, deps.AuthService)
	assert.NotNil(t, deps.AuditService)
	assert.NotNil(t, deps.AuthMiddleware)
}
