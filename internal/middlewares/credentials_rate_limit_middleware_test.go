package middlewares_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
)

func TestCredentialsRateLimitMiddleware_Use(t *testing.T) {
	now := time.Now()
	newHandler := func(t *testing.T, called *int) http.HandlerFunc {
		middleware := middlewares.NewCredentialsRateLimitMiddlewareWithClock(t.Context(), 60, 2, func() time.Time { return now })
		return middleware.Use(func(w http.ResponseWriter, r *http.Request) {
			*called++
			w.WriteHeader(http.StatusOK)
		})
	}
	serve := func(handler http.HandlerFunc, remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler(w, req)
		return w
	}

	t.Run("success - allows up to the burst and sets headers", func(t *testing.T) {
		called := 0
		handler := newHandler(t, &called)

		w := serve(handler, "10.0.0.1:1111")

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "2", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "1", w.Header().Get("X-RateLimit-Remaining"))
		assert.Equal(t, http.StatusOK, serve(handler, "10.0.0.1:1111").Code)
		assert.Equal(t, 2, called)
	})

	t.Run("error - rejects after the burst without calling next", func(t *testing.T) {
		called := 0
		handler := newHandler(t, &called)
		serve(handler, "10.0.0.1:1111")
		serve(handler, "10.0.0.1:1111")

		w := serve(handler, "10.0.0.1:1111")

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
		var body api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, "rateLimit.exceeded", body.Message)
		assert.Equal(t, 2, called)
	})

	t.Run("success - other clients have their own bucket", func(t *testing.T) {
		called := 0
		handler := newHandler(t, &called)
		serve(handler, "10.0.0.1:1111")
		serve(handler, "10.0.0.1:1111")

		assert.Equal(t, http.StatusOK, serve(handler, "10.0.0.2:1111").Code)
	})

	t.Run("success - refills at the per-minute rate", func(t *testing.T) {
		called := 0
		handler := newHandler(t, &called)
		serve(handler, "10.0.0.1:1111")
		serve(handler, "10.0.0.1:1111")

		now = now.Add(1100 * time.Millisecond)

		assert.Equal(t, http.StatusOK, serve(handler, "10.0.0.1:1111").Code)
	})
}
