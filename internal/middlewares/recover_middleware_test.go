package middlewares_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoverMiddleware_Use(t *testing.T) {
	var buf bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(originalLogger)

	middleware := middlewares.NewRecoverMiddleware()

	t.Run("success", func(t *testing.T) {
		buf.Reset()
		handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("ok"))
		}))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, "ok", w.Body.String())
		assert.Empty(t, buf.String())
	})

	t.Run("error - panic returns 500 JSON", func(t *testing.T) {
		buf.Reset()
		handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("boom")
		}))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, "internalServerError", body["error"])
	})

	t.Run("error - panic logs message, panic and stack", func(t *testing.T) {
		buf.Reset()
		handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("boom")
		}))

		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

		var entry map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
		assert.Equal(t, "panic recovered", entry["msg"])
		assert.Equal(t, "ERROR", entry["level"])
		assert.Equal(t, "boom", entry["panic"])
		assert.NotEmpty(t, entry["stack"])
	})

	t.Run("error - panic after write keeps response", func(t *testing.T) {
		buf.Reset()
		handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("partial"))
			panic("boom")
		}))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.Equal(t, "partial", w.Body.String())
		assert.Contains(t, buf.String(), "panic recovered")
	})

	t.Run("error - ErrAbortHandler re-panics", func(t *testing.T) {
		buf.Reset()
		handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		}))

		assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		})
		assert.Empty(t, buf.String())
	})
}
