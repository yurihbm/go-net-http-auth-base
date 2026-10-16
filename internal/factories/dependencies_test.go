package factories

import (
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
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
