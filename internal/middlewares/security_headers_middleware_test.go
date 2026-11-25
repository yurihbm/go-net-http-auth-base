package middlewares_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeadersMiddleware_Use(t *testing.T) {
	serve := func(secure bool) *httptest.ResponseRecorder {
		handler := middlewares.NewSecurityHeadersMiddleware(secure).Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w
	}

	t.Run("success - sets the baseline headers and calls next", func(t *testing.T) {
		w := serve(false)

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
		assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
	})

	t.Run("success - not secure omits HSTS", func(t *testing.T) {
		assert.Empty(t, serve(false).Header().Get("Strict-Transport-Security"))
	})

	t.Run("success - secure adds HSTS", func(t *testing.T) {
		assert.Equal(t, "max-age=31536000; includeSubDomains", serve(true).Header().Get("Strict-Transport-Security"))
	})
}
