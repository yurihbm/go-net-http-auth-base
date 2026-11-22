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

	"github.com/google/uuid"
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

	t.Run("returns an error when the context deadline passes", func(t *testing.T) {
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

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := provider.Send(ctx, msg)

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

	newRecordingProvider := func(url string, waits *[]time.Duration) domain.EmailProvider {
		return providers.NewResendEmailProviderWithWait("re_key", "from@example.com", url, func(ctx context.Context, d time.Duration) error {
			*waits = append(*waits, d)
			return ctx.Err()
		})
	}

	t.Run("success - retries a 5xx with the same idempotency key", func(t *testing.T) {
		var keys []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if len(keys) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.NoError(t, err)
		require.Len(t, keys, 2)
		assert.NotEmpty(t, keys[0])
		assert.Equal(t, keys[0], keys[1])
		parsed, err := uuid.Parse(keys[0])
		require.NoError(t, err)
		assert.Equal(t, uuid.Version(7), parsed.Version())
		assert.Equal(t, []time.Duration{200 * time.Millisecond}, waits)
	})

	t.Run("success - uses a new idempotency key per Send", func(t *testing.T) {
		var keys []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
		}))
		defer server.Close()
		var waits []time.Duration
		provider := newRecordingProvider(server.URL, &waits)

		require.NoError(t, provider.Send(context.Background(), msg))
		require.NoError(t, provider.Send(context.Background(), msg))

		require.Len(t, keys, 2)
		assert.NotEqual(t, keys[0], keys[1])
	})

	t.Run("success - honors Retry-After on 429 within the cap", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if requests == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.NoError(t, err)
		assert.Equal(t, []time.Duration{time.Second}, waits)
	})

	t.Run("success - ignores Retry-After above the cap", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if requests == 1 {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.NoError(t, err)
		assert.Equal(t, []time.Duration{200 * time.Millisecond}, waits)
	})

	t.Run("error - does not retry a non-retryable 4xx", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusUnprocessableEntity)
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.Error(t, err)
		assert.Equal(t, 1, requests)
		assert.Empty(t, waits)
	})

	t.Run("error - stops after three failed attempts", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.EqualError(t, err, "resend: unexpected status 503")
		assert.Equal(t, 3, requests)
		assert.Equal(t, []time.Duration{200 * time.Millisecond, 400 * time.Millisecond}, waits)
	})

	t.Run("error - retries transport errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := server.URL
		server.Close()
		var waits []time.Duration

		err := newRecordingProvider(url, &waits).Send(context.Background(), msg)

		require.Error(t, err)
		assert.Len(t, waits, 2)
	})

	t.Run("error - stops retrying when the context is cancelled during backoff", func(t *testing.T) {
		var requests int
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		provider := providers.NewResendEmailProviderWithWait("re_key", "from@example.com", server.URL, func(ctx context.Context, d time.Duration) error {
			cancel()
			return ctx.Err()
		})

		err := provider.Send(ctx, msg)

		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, requests)
	})

	t.Run("success - retries a concurrent idempotent request conflict", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if requests == 1 {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"name":"concurrent_idempotent_requests","message":"in progress"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.NoError(t, err)
		assert.Equal(t, 2, requests)
	})

	t.Run("error - does not retry another 409", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"name":"invalid_idempotent_request","message":"payload differs"}`))
		}))
		defer server.Close()
		var waits []time.Duration

		err := newRecordingProvider(server.URL, &waits).Send(context.Background(), msg)

		require.EqualError(t, err, "resend: unexpected status 409: invalid_idempotent_request: payload differs")
		assert.Equal(t, 1, requests)
		assert.Empty(t, waits)
	})

	t.Run("error - stops retrying when the total budget is exhausted", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		provider := providers.NewResendEmailProviderWithTotalTimeout("re_key", "from@example.com", server.URL, 50*time.Millisecond)

		err := provider.Send(context.Background(), msg)

		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, 1, requests)
	})

	t.Run("success - bounds the whole send with a total deadline", func(t *testing.T) {
		var deadline time.Time
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		provider := providers.NewResendEmailProviderWithWait("re_key", "from@example.com", server.URL, func(ctx context.Context, d time.Duration) error {
			deadline, _ = ctx.Deadline()
			return ctx.Err()
		})

		_ = provider.Send(context.Background(), msg)

		assert.WithinDuration(t, time.Now().Add(15*time.Second), deadline, time.Second)
	})
}
