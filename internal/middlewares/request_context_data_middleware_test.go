package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"

	"github.com/stretchr/testify/assert"
)

func TestNewRequestContextDataMiddleware(t *testing.T) {
	t.Run("should create new request context data middleware", func(t *testing.T) {
		middleware := NewRequestContextDataMiddleware()
		assert.NotNil(t, middleware)
	})
}

func TestRequestContextDataMiddleware_Use(t *testing.T) {
	middleware := NewRequestContextDataMiddleware()

	t.Run("should add request context data pointer to request context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		handler := middleware.Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, ok := r.Context().Value(
					api.RequestContextDataKey,
				).(*api.RequestContextData)
				if !ok {
					t.Error("RequestContextData not found in context")
					return
				}
			}),
		)
		handler.ServeHTTP(rr, req)
	})
}
