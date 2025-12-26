package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimitMiddleware(t *testing.T) {
	// Limit: 1 req/sec, Burst: 2
	middleware := NewRateLimitMiddleware(rate.Limit(1), 2)
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
}
