package middlewares_test

import (
	"context"
	"encoding/json"
	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/shared"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
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
	now := time.Now()
	middleware := middlewares.NewRateLimitMiddlewareWithClock(t.Context(), rate.Limit(1), 2, func() time.Time { return now })
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
	assert.Equal(t, "rateLimit.exceeded", response.Error)
	assert.Empty(t, response.Message)
	assert.Equal(t, "1", w.Header().Get("Retry-After"))

	// 4. Different IP - should pass
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.2:1234"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req2)
	assert.Equal(t, http.StatusOK, w.Code)

	// 5. Wait for refill
	now = now.Add(1100 * time.Millisecond) // Advance > 1 sec
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

	t.Run("different client ips behind the same remote addr have independent buckets", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		serveAs := func(clientIP string) int {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "10.0.0.9:1111"
			req = req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{ClientIP: clientIP}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			return w.Code
		}

		assert.Equal(t, http.StatusOK, serveAs("203.0.113.1"))
		assert.Equal(t, http.StatusOK, serveAs("203.0.113.2"))
		assert.Equal(t, http.StatusTooManyRequests, serveAs("203.0.113.1"))
	})

	t.Run("ipv6 addresses in the same /64 share a bucket", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "[2001:db8:1:2::1]:1111"))
		assert.Equal(t, http.StatusTooManyRequests, serveFrom(handler, "[2001:db8:1:2:ffff::9]:2222"))
	})

	t.Run("ipv6 addresses in different /64 prefixes have independent buckets", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "[2001:db8:1:2::1]:1111"))
		assert.Equal(t, http.StatusOK, serveFrom(handler, "[2001:db8:1:3::1]:1111"))
	})

	t.Run("ipv4-mapped ipv6 shares the bucket of the ipv4 address", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "10.0.0.4:1111"))
		assert.Equal(t, http.StatusTooManyRequests, serveFrom(handler, "[::ffff:10.0.0.4]:1111"))
	})

	t.Run("unparsable addresses fall back to the raw string", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "not-an-ip"))
		assert.Equal(t, http.StatusTooManyRequests, serveFrom(handler, "not-an-ip"))
		assert.Equal(t, http.StatusOK, serveFrom(handler, "other-key"))
	})

	t.Run("remote addr without port still works", func(t *testing.T) {
		handler := newRateLimitedHandler(t, 1)

		assert.Equal(t, http.StatusOK, serveFrom(handler, "10.0.0.3"))
		assert.Equal(t, http.StatusTooManyRequests, serveFrom(handler, "10.0.0.3"))
	})

	t.Run("error - records the too many requests error when the limit is exceeded", func(t *testing.T) {
		now := time.Now()
		handler := middlewares.NewRateLimitMiddlewareWithClock(t.Context(), rate.Limit(1), 1, func() time.Time { return now }).
			Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		data := &shared.RequestContextData{}
		serve := func() int {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			req = req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, data))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			return w.Code
		}

		assert.Equal(t, http.StatusOK, serve())
		assert.Nil(t, data.Error)
		assert.Equal(t, http.StatusTooManyRequests, serve())

		var tooManyErr *domain.TooManyRequestsError
		assert.ErrorAs(t, data.Error, &tooManyErr)
		assert.EqualError(t, data.Error, "rateLimit.exceeded")
	})

	t.Run("error - rounds Retry-After up to the next whole second", func(t *testing.T) {
		now := time.Now()
		handler := middlewares.NewRateLimitMiddlewareWithClock(t.Context(), rate.Limit(0.5), 1, func() time.Time { return now }).
			Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		serve := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			return w
		}

		assert.Equal(t, http.StatusOK, serve().Code)
		w := serve()
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "2", w.Header().Get("Retry-After"))
	})
}

func TestNewRateLimitMiddleware(t *testing.T) {
	t.Run("cleanup goroutine stops when the context is cancelled", func(t *testing.T) {
		// synctest.Test fails if a goroutine started in the bubble is still
		// blocked after the function returns, so leaks are caught without
		// counting goroutines from other tests.
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			middlewares.NewRateLimitMiddleware(ctx, rate.Limit(1), 1)

			cancel()
		})
	})
}
