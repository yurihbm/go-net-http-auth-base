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

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestLogEmailProvider_Send(t *testing.T) {
	msg := domain.EmailMessage{
		To:      "user@example.com",
		Subject: "Verify your email",
		Text:    "https://app.example.com/verify?token=abc",
		HTML:    "<a href=\"https://app.example.com/verify?token=abc\">verify</a>",
	}

	t.Run("logs recipient and subject only without the body", func(t *testing.T) {
		buf := captureLogs(t)

		err := providers.NewLogEmailProvider(false).Send(context.Background(), msg)

		require.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "user@example.com")
		assert.Contains(t, output, "Verify your email")
		assert.NotContains(t, output, "token=abc")
		assert.NotContains(t, output, "text=")
		assert.NotContains(t, output, "html=")
	})

	t.Run("logs the text body when enabled", func(t *testing.T) {
		buf := captureLogs(t)

		err := providers.NewLogEmailProvider(true).Send(context.Background(), msg)

		require.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "user@example.com")
		assert.Contains(t, output, "Verify your email")
		assert.Contains(t, output, "token=abc")
		assert.NotContains(t, output, "html=")
	})
}
