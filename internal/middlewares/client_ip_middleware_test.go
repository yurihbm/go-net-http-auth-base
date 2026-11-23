package middlewares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/shared"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientIPMiddleware(t *testing.T) {
	assert.NotNil(t, middlewares.NewClientIPMiddleware(nil))
}

func TestClientIPMiddleware_Use(t *testing.T) {
	proxies := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/8"),
	}

	tests := []struct {
		name       string
		trusted    []netip.Prefix
		remoteAddr string
		xff        []string
		want       string
	}{
		{"no proxies configured ignores XFF", nil, "203.0.113.9:4000", []string{"1.1.1.1"}, "203.0.113.9"},
		{"untrusted remote with spoofed XFF is ignored", proxies, "203.0.113.9:4000", []string{"1.1.1.1"}, "203.0.113.9"},
		{"trusted proxy without XFF uses the remote", proxies, "10.0.0.1:4000", nil, "10.0.0.1"},
		{"trusted proxy single hop", proxies, "10.0.0.1:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"multiple trusted hops", proxies, "10.0.0.1:4000", []string{"198.51.100.7, 10.0.0.2, 10.0.0.3"}, "198.51.100.7"},
		{"client supplied left entries are ignored", proxies, "10.0.0.1:4000", []string{"1.1.1.1, 198.51.100.7"}, "198.51.100.7"},
		{"multiple XFF headers are joined in order", proxies, "10.0.0.1:4000", []string{"1.1.1.1", "198.51.100.7, 10.0.0.2"}, "198.51.100.7"},
		{"all entries trusted uses the leftmost", proxies, "10.0.0.1:4000", []string{"10.0.0.5, 10.0.0.2"}, "10.0.0.5"},
		{"ipv6 client behind trusted proxy", proxies, "10.0.0.1:4000", []string{"2001:db8::7"}, "2001:db8::7"},
		{"ipv6 trusted proxy", proxies, "[fd00::1]:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"ipv4-mapped ipv6 is unmapped", proxies, "10.0.0.1:4000", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
		{"ipv4-mapped remote matches trusted ipv4 prefix", proxies, "[::ffff:10.0.0.1]:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"invalid rightmost entry falls back to the remote", proxies, "10.0.0.1:4000", []string{"198.51.100.7, garbage"}, "10.0.0.1"},
		{"invalid entry stops the walk at the last trusted hop", proxies, "10.0.0.1:4000", []string{"198.51.100.7, garbage, 10.0.0.2"}, "10.0.0.2"},
		{"only invalid entries fall back to the remote", proxies, "10.0.0.1:4000", []string{"garbage"}, "10.0.0.1"},
		{"untrusted ipv4-mapped remote is unmapped", proxies, "[::ffff:203.0.113.9]:4000", nil, "203.0.113.9"},
		{"remote without port", proxies, "10.0.0.1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"untrusted remote without port", proxies, "203.0.113.9", []string{"1.1.1.1"}, "203.0.113.9"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			data := &shared.RequestContextData{}
			req = req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, data))

			called := false
			middlewares.NewClientIPMiddleware(tc.trusted).Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			})).ServeHTTP(httptest.NewRecorder(), req)

			require.True(t, called)
			assert.Equal(t, tc.want, data.ClientIP)
		})
	}

	t.Run("bounds the walk over a huge X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:4000"
		req.Header.Set("X-Forwarded-For", "198.51.100.7"+strings.Repeat(", 10.0.0.2", 100000))
		data := &shared.RequestContextData{}
		req = req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, data))

		middlewares.NewClientIPMiddleware(proxies).Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, "10.0.0.2", data.ClientIP)
	})

	t.Run("finds the client within the hop cap", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:4000"
		req.Header.Set("X-Forwarded-For", "198.51.100.7"+strings.Repeat(", 10.0.0.2", 31))
		data := &shared.RequestContextData{}
		req = req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, data))

		middlewares.NewClientIPMiddleware(proxies).Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, "198.51.100.7", data.ClientIP)
	})

	t.Run("does nothing without request context data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		called := false

		middlewares.NewClientIPMiddleware(proxies).Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(httptest.NewRecorder(), req)

		assert.True(t, called)
	})
}
