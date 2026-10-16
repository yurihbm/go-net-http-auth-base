package providers_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogEmailProvider_Send(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	provider := providers.NewLogEmailProvider()

	err := provider.Send(context.Background(), domain.EmailMessage{
		To:      "user@example.com",
		Subject: "Verify your email",
		Text:    "https://app.example.com/verify?token=abc",
	})

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "user@example.com")
	assert.Contains(t, output, "Verify your email")
	assert.Contains(t, output, "https://app.example.com/verify?token=abc")
}
