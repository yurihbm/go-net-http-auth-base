package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/config"
)

func TestWarnMissingTrustedProxies(t *testing.T) {
	run := func(t *testing.T, cfg config.Config) string {
		t.Helper()
		var buf bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		t.Cleanup(func() { slog.SetDefault(previous) })

		warnMissingTrustedProxies(context.Background(), &cfg)
		return buf.String()
	}

	t.Run("success - warns in production with an empty list", func(t *testing.T) {
		out := run(t, config.Config{Env: "production"})

		assert.Contains(t, out, "level=WARN")
		assert.Contains(t, out, "TRUSTED_PROXIES")
	})

	t.Run("success - does not warn in production with a configured list", func(t *testing.T) {
		out := run(t, config.Config{
			Env:            "production",
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")},
		})

		assert.Empty(t, out)
	})

	t.Run("success - does not warn outside production", func(t *testing.T) {
		out := run(t, config.Config{Env: "development"})

		assert.Empty(t, out)
	})
}
