package providers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResendEmailProvider_Send(t *testing.T) {
	msg := domain.EmailMessage{
		To:      "user@example.com",
		Subject: "Verify your email",
		HTML:    "<p>hello</p>",
		Text:    "hello",
	}

	t.Run("sends the expected request", func(t *testing.T) {
		var gotMethod, gotPath, gotAuth, gotContentType, gotUserAgent string
		var gotBody map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			gotContentType = r.Header.Get("Content-Type")
			gotUserAgent = r.Header.Get("User-Agent")
			require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		provider := providers.NewResendEmailProvider("re_key", "App <no-reply@example.com>", server.URL)

		err := provider.Send(context.Background(), msg)

		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, gotMethod)
		assert.Equal(t, "/emails", gotPath)
		assert.Equal(t, "Bearer re_key", gotAuth)
		assert.Equal(t, "application/json", gotContentType)
		assert.Equal(t, "go-net-http-auth-base/1.0", gotUserAgent)
		assert.Equal(t, map[string]any{
			"from":    "App <no-reply@example.com>",
			"to":      []any{"user@example.com"},
			"subject": "Verify your email",
			"html":    "<p>hello</p>",
			"text":    "hello",
		}, gotBody)
	})

	t.Run("returns an error on non-2xx status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}))
		defer server.Close()

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)

		err := provider.Send(context.Background(), msg)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "422")
	})

	t.Run("surfaces the error name and message from the response body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"name":"validation_error","message":"domain is not verified"}`))
		}))
		defer server.Close()

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)

		err := provider.Send(context.Background(), msg)

		require.EqualError(t, err, "resend: unexpected status 403: validation_error: domain is not verified")
	})

	t.Run("falls back to the status when the body is not parseable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		}))
		defer server.Close()

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)

		err := provider.Send(context.Background(), msg)

		require.EqualError(t, err, "resend: unexpected status 502")
	})

	t.Run("falls back to the status when the body has no name or message", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"foo":"bar"}`))
		}))
		defer server.Close()

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)

		err := provider.Send(context.Background(), msg)

		require.EqualError(t, err, "resend: unexpected status 500")
	})

	t.Run("bounds the error body it reads", func(t *testing.T) {
		huge := `{"name":"validation_error","message":"` + strings.Repeat("a", 1<<20) + `"}`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(huge))
		}))
		defer server.Close()

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)

		err := provider.Send(context.Background(), msg)

		require.Error(t, err)
		assert.Less(t, len(err.Error()), 8192)
		assert.Contains(t, err.Error(), "422")
	})

	t.Run("returns an error when the request times out", func(t *testing.T) {
		t.Cleanup(providers.SetResendHTTPTimeout(50 * time.Millisecond))
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer server.Close()
		defer close(release)

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)

		err := provider.Send(context.Background(), msg)

		require.Error(t, err)
	})

	t.Run("returns an error when the context is cancelled", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer server.Close()
		defer close(release)

		provider := providers.NewResendEmailProvider("re_key", "from@example.com", server.URL)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := provider.Send(ctx, msg)

		require.ErrorIs(t, err, context.Canceled)
	})
}
