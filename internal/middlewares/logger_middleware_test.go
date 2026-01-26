package middlewares_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
)

func TestNewLoggerMiddleware(t *testing.T) {
	t.Run("should create new logger middleware", func(t *testing.T) {
		middleware := middlewares.NewLoggerMiddleware()
		assert.NotNil(t, middleware)
	})
}

func TestLoggerMiddleware_Use(t *testing.T) {
	// Setup log capture
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(handler)
	originalLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(originalLogger)

	middleware := middlewares.NewLoggerMiddleware()

	t.Run("should log info for 200 OK", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-path", nil)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "HTTP Request")
		assert.Contains(t, logOutput, "\"level\":\"INFO\"")
		assert.Contains(t, logOutput, "\"method\":\"GET\"")
		assert.Contains(t, logOutput, "\"path\":\"/test-path\"")
		assert.Contains(t, logOutput, "\"status\":200")
	})

	t.Run("should log warn for 400 Bad Request", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("POST", "/api/create", nil)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "HTTP Request")
		assert.Contains(t, logOutput, "\"level\":\"WARN\"")
		assert.Contains(t, logOutput, "\"method\":\"POST\"")
		assert.Contains(t, logOutput, "\"path\":\"/api/create\"")
		assert.Contains(t, logOutput, "\"status\":400")
	})

	t.Run("should log error for 500 Internal Server Error", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("DELETE", "/api/delete", nil)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "HTTP Request")
		assert.Contains(t, logOutput, "\"level\":\"ERROR\"")
		assert.Contains(t, logOutput, "\"method\":\"DELETE\"")
		assert.Contains(t, logOutput, "\"path\":\"/api/delete\"")
		assert.Contains(t, logOutput, "\"status\":500")
	})

	t.Run("should capture duration", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "\"duration\":")
	})

	t.Run("should capture user agent and ip", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "TestAgent/1.0")
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "\"userAgent\":\"TestAgent/1.0\"")
		assert.Contains(t, logOutput, "\"ip\":\"192.168.1.1:1234\"")
	})

	t.Run("should log requestUUID when present", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-auth", nil)
		ctx := context.WithValue(
			req.Context(),
			api.RequestContextDataKey,
			&api.RequestContextData{
				RequestUUID: "test-req-uuid",
			},
		)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "\"requestUUID\":\"test-req-uuid\"")
	})

	t.Run("should not log requestUUID when not present", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-auth", nil)
		ctx := context.WithValue(
			req.Context(),
			api.RequestContextDataKey,
			&api.RequestContextData{},
		)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logOutput := buf.String()
		assert.NotContains(t, logOutput, "\"requestUUID\"")
	})

	t.Run("should log userUUID when present", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate setting UserUUID in the context
			if data, ok := r.Context().Value(
				api.RequestContextDataKey,
			).(*api.RequestContextData); ok {
				data.UserUUID = "test-user-uuid"
			}
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-auth", nil)
		ctx := context.WithValue(
			req.Context(),
			api.RequestContextDataKey,
			&api.RequestContextData{},
		)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "\"userUUID\":\"test-user-uuid\"")
	})

	t.Run("should not log userUUID when not present", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-no-auth", nil)
		ctx := context.WithValue(
			req.Context(),
			api.RequestContextDataKey,
			&api.RequestContextData{},
		)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logOutput := buf.String()
		assert.NotContains(t, logOutput, "\"userUUID\"")
	})

	t.Run("should log error when present", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate setting error in the context
			if data, ok := r.Context().Value(
				api.RequestContextDataKey,
			).(*api.RequestContextData); ok {
				data.Error = errors.New("some error occurred")
			}
			w.WriteHeader(http.StatusInternalServerError)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-auth", nil)
		ctx := context.WithValue(
			req.Context(),
			api.RequestContextDataKey,
			&api.RequestContextData{},
		)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "\"error\":\"some error occurred\"")
	})

	t.Run("should not log error when not present", func(t *testing.T) {
		buf.Reset()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test-no-auth", nil)
		ctx := context.WithValue(
			req.Context(),
			api.RequestContextDataKey,
			&api.RequestContextData{},
		)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		logOutput := buf.String()
		assert.NotContains(t, logOutput, "\"error\"")
	})
}
