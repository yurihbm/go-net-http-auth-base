package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewRequestUUIDMiddleware(t *testing.T) {
	t.Run("should create new request UUID middleware", func(t *testing.T) {
		middleware := NewRequestUUIDMiddleware()
		assert.NotNil(t, middleware)
	})
}

func TestRequestUUIDMiddleware_Use(t *testing.T) {
	middleware := NewRequestUUIDMiddleware()

	t.Run("should add request UUID to context and response header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		handler := middleware.Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reqContextData, ok := r.Context().Value(
					api.RequestContextDataKey,
				).(*api.RequestContextData)
				if !ok {
					t.Error("RequestContextData not found in context")
					return
				}

				if reqContextData.RequestUUID == "" {
					t.Error("RequestUUID not set in RequestContextData")
				}

				if _, err := uuid.Parse(reqContextData.RequestUUID); err != nil {
					t.Errorf("Invalid UUID format: %v", err)
				}
			}),
		)
		handler.ServeHTTP(rr, req)

		// Check if X-Request-UUID header is set
		requestIDHeader := rr.Header().Get("X-Request-UUID")
		if requestIDHeader == "" {
			t.Error("X-Request-UUID header not set")
		}
	})

	t.Run("should preserve existing RequestContextData in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, api.RequestContextDataKey, &api.RequestContextData{
			UserUUID: "existing-user-uuid",
		})
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		handler := middleware.Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reqContextData, ok := r.Context().Value(
					api.RequestContextDataKey,
				).(*api.RequestContextData)

				if !ok {
					t.Error("RequestContextData not found in context")
					return
				}

				if reqContextData.UserUUID != "existing-user-uuid" {
					t.Errorf(
						"Expected UserUUID to be 'existing-user-uuid', got '%s'",
						reqContextData.UserUUID,
					)
				}
			}),
		)

		handler.ServeHTTP(rr, req)
	})
}
