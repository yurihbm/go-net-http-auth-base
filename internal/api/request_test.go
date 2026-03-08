package api_test

import (
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"

	"github.com/stretchr/testify/assert"
)

func TestGetClientMetadata(t *testing.T) {
	t.Run("returns X-Forwarded-For first address", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.5, 192.168.1.1")
		req.Header.Set("User-Agent", "TestAgent/1.0")

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "203.0.113.5", ip)
		assert.Equal(t, "TestAgent/1.0", ua)
	})

	t.Run("falls back to X-Real-IP when X-Forwarded-For absent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "198.51.100.7")
		req.Header.Set("User-Agent", "RealIPAgent/2.0")

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "198.51.100.7", ip)
		assert.Equal(t, "RealIPAgent/2.0", ua)
	})

	t.Run("falls back to RemoteAddr when no proxy headers set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "10.0.0.1", ip)
		assert.Empty(t, ua)
	})

	t.Run("X-Forwarded-For takes priority over X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		req.Header.Set("X-Real-IP", "5.6.7.8")

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "1.2.3.4", ip)
	})

	t.Run("strips port from RemoteAddr with no proxy headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.0.42:9999"

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "192.168.0.42", ip)
	})

	t.Run("returns RemoteAddr as-is when it has no port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.0.42"

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "192.168.0.42", ip)
	})
}
