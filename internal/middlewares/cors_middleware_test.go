package middlewares_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
)

func getTestCORSMiddleware(origins, methods, headers, exposeHeaders []string, credentials bool, maxAge string) *middlewares.CORSMiddleware {
	return middlewares.NewCORSMiddleware(origins, methods, headers, exposeHeaders, credentials, maxAge)
}

func TestNewCORSMiddleware(t *testing.T) {
	t.Run("should create new CORS middleware", func(t *testing.T) {
		middleware := middlewares.NewCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{"X-Total-Count"},
			true,
			"3600",
		)

		assert.NotNil(t, middleware)
	})
}

func TestCORSMiddlewareUse(t *testing.T) {
	t.Run("success - allowed origin with all headers set", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST", "PUT"},
			[]string{"Content-Type", "Authorization"},
			[]string{"X-Total-Count", "X-Page"},
			true,
			"3600",
		)

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w.Header().Get("Vary"))
		assert.Equal(t, "GET, POST, PUT", w.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "X-Total-Count, X-Page", w.Header().Get("Access-Control-Expose-Headers"))
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "3600", w.Header().Get("Access-Control-Max-Age"))
	})

	t.Run("success - wildcard origin", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"*"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"7200",
		)

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://any-origin.com")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w.Header().Get("Vary"))
		assert.Equal(t, "GET, POST", w.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type", w.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "7200", w.Header().Get("Access-Control-Max-Age"))
	})

	t.Run("success - disallowed origin", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://different-origin.com")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "", w.Header().Get("Vary"))
	})

	t.Run("success - missing origin header", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		// No Origin header
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "", w.Header().Get("Vary"))
	})

	t.Run("success - OPTIONS preflight request", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST", "DELETE"},
			[]string{"Content-Type", "Authorization"},
			[]string{"X-Request-ID"},
			true,
			"86400",
		)

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled, "next handler should not be called for OPTIONS")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w.Header().Get("Vary"))
		assert.Equal(t, "GET, POST, DELETE", w.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "X-Request-ID", w.Header().Get("Access-Control-Expose-Headers"))
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("success - multiple allowed origins", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000", "http://localhost:3001", "https://example.com"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		// Test first origin
		req1 := httptest.NewRequest("GET", "/test", nil)
		req1.Header.Set("Origin", "http://localhost:3000")
		w1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w1, req1)
		assert.Equal(t, "http://localhost:3000", w1.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w1.Header().Get("Vary"))

		// Test second origin
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.Header.Set("Origin", "http://localhost:3001")
		w2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w2, req2)
		assert.Equal(t, "http://localhost:3001", w2.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w2.Header().Get("Vary"))

		// Test third origin
		req3 := httptest.NewRequest("GET", "/test", nil)
		req3.Header.Set("Origin", "https://example.com")
		w3 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w3, req3)
		assert.Equal(t, "https://example.com", w3.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w3.Header().Get("Vary"))
	})

	t.Run("success - empty methods list", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type", w.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("success - empty headers list", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST"},
			[]string{},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "GET, POST", w.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("success - expose headers configured", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{"X-Total-Count", "X-Page", "X-Per-Page"},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "X-Total-Count, X-Page, X-Per-Page", w.Header().Get("Access-Control-Expose-Headers"))
	})

	t.Run("success - empty expose headers list", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "", w.Header().Get("Access-Control-Expose-Headers"))
	})

	t.Run("success - credentials disabled", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("success - empty max age defaults to 86400", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
	})

	t.Run("success - vary header set for allowed origins", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "Origin", w.Header().Get("Vary"), "Vary header should be set for allowed origins")
	})

	t.Run("success - vary header not set for disallowed origins", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET"},
			[]string{"Content-Type"},
			[]string{},
			false,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://disallowed.com")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, "", w.Header().Get("Vary"), "Vary header should not be set for disallowed origins")
	})

	t.Run("success - wildcard origin does not set credentials even if configured", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"*"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{},
			true,
			"7200",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://any-origin.com")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Credentials"), "credentials should not be set with wildcard origin")
	})

	t.Run("success - specific origin allows credentials when configured", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"http://localhost:3000"},
			[]string{"GET", "POST"},
			[]string{"Content-Type"},
			[]string{},
			true,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"), "credentials should be set for specific origin")
	})

	t.Run("success - different HTTP methods preserved", func(t *testing.T) {
		middleware := getTestCORSMiddleware(
			[]string{"*"},
			[]string{"GET", "POST", "PUT", "DELETE", "PATCH"},
			[]string{"Content-Type", "Authorization"},
			[]string{},
			true,
			"3600",
		)

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, method := range methods {
			req := httptest.NewRequest(method, "/test", nil)
			req.Header.Set("Origin", "http://any-origin.com")
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "method %s should work", method)
			assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		}
	})
}
