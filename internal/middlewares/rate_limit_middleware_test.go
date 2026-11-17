package middlewares_test

import (
	"context"
	"encoding/json"
	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/middlewares"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func newRateLimitedHandler(t *testing.T, burst int) http.Handler {
	middleware := middlewares.NewRateLimitMiddleware(t.Context(), rate.Limit(0.001), burst)
	return middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func serveFrom(handler http.Handler, remoteAddr string) int {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

func TestRateLimitMiddleware(t *testing.T) {
	// Limit: 1 req/sec, Burst: 2
	middleware := middlewares.NewRateLimitMiddleware(t.Context(), rate.Limit(1), 2)
	handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. First request - should pass
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "2", w.Header().Get("X-RateLimit-Limit"))

	// 2. Second request - should pass
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// 3. Third request - should fail (burst exhausted)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var response api.ResponseBody[any]
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "rateLimit.exceeded", response.Message)
	assert.Equal(t, "too many requests", response.Error)

	// 4. Different IP - should pass
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.2:1234"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req2)
	assert.Equal(t, http.StatusOK, w.Code)

	// 5. Wait for refill
	time.Sleep(1100 * time.Millisecond) // Wait > 1 sec
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	t.Run("same ip with different ports shares a bucket", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "10.0.0.1:1111"))
		assert.Equal(t, http.StatusTooManyRequests, serveFrom(handler, "10.0.0.1:2222"))
	})

	t.Run("different ips have independent buckets", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "10.0.0.1:1111"))
		assert.Equal(t, http.StatusOK, serveFrom(handler, "10.0.0.2:1111"))
	})

	t.Run("remote addr without port still works", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "10.0.0.3"))
		assert.Equal(t, http.StatusTooManyRequests, serveFrom(handler, "10.0.0.3"))
	})
}

func TestNewRateLimitMiddleware(t *testing.T) {
	t.Run("cleanup goroutine stops when the context is cancelled", func(t *testing.T) {
		const instances = 20
		const eventuallyOverhead = 5
		baseline := runtime.NumGoroutine()

		ctx, cancel := context.WithCancel(context.Background())
		for range instances {
			middlewares.NewRateLimitMiddleware(ctx, rate.Limit(1), 1)
		}
		assert.GreaterOrEqual(t, runtime.NumGoroutine(), baseline+instances)

		cancel()

		assert.Eventually(t, func() bool {
			return runtime.NumGoroutine() <= baseline+eventuallyOverhead
		}, 2*time.Second, 10*time.Millisecond)
	})
}
