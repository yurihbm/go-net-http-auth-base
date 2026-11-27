package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type passwordDTO struct {
	Password string `json:"password" validate:"required,min=8,max=64,maxbytes=72"`
}

type testDTO struct {
	Name  string `json:"name"  validate:"required"`
	Email string `json:"email" validate:"required,email"`
	Age   int    `json:"age"   validate:"omitempty,min=1"`
}

type flagKeyDTO struct {
	Key string `json:"key" validate:"flagkey"`
}

func TestDecodeAndValidate(t *testing.T) {
	t.Run("valid body returns decoded value", func(t *testing.T) {
		body, _ := json.Marshal(testDTO{Name: "Alice", Email: "alice@example.com"})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		result, err := api.DecodeAndValidate[testDTO](req)

		assert.NoError(t, err)
		assert.Equal(t, "Alice", result.Name)
		assert.Equal(t, "alice@example.com", result.Email)
	})

	t.Run("invalid JSON returns ValidationError with body key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(`not json`)))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["body"])
	})

	t.Run("invalid JSON does not leak decoder internals", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(`{"name":123,"email":"a@b.com"}`)))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, "request body must be valid JSON", valErr.Details()["body"])
	})

	t.Run("unknown field message does not echo decoder text", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(`{"name":"x","email":"x@x.com","unknown":"y"}`)))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, "request body contains an unknown field", valErr.Details()["body"])
	})

	t.Run("password accepts 64 ASCII characters", func(t *testing.T) {
		body, _ := json.Marshal(passwordDTO{Password: strings.Repeat("a", 64)})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[passwordDTO](req)

		assert.NoError(t, err)
	})

	t.Run("password rejects 65 characters", func(t *testing.T) {
		body, _ := json.Marshal(passwordDTO{Password: strings.Repeat("a", 65)})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[passwordDTO](req)

		var valErr *domain.ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["password"])
	})

	t.Run("password rejects 64 characters over 72 bytes", func(t *testing.T) {
		body, _ := json.Marshal(passwordDTO{Password: strings.Repeat("😀", 30)})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[passwordDTO](req)

		var valErr *domain.ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, "must be at most 72 bytes long", valErr.Details()["password"])
	})

	t.Run("body over 1 MiB returns ValidationError with body key", func(t *testing.T) {
		body := []byte(`{"name":"` + strings.Repeat("a", 1<<20) + `","email":"alice@example.com"}`)
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.Equal(t, "request body too large", valErr.Details()["body"])
	})

	t.Run("unknown field returns ValidationError with body key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(`{"name":"x","email":"x@x.com","unknown":"y"}`)))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["body"])
	})

	t.Run("missing required field returns ValidationError with field key", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"email": "alice@example.com"})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["name"])
	})

	t.Run("invalid email returns ValidationError with field key", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"name": "Alice", "email": "not-an-email"})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["email"])
	})

	t.Run("omitempty field below min returns ValidationError", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"name": "Alice", "email": "alice@example.com", "age": 0})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		// age=0 is zero value, omitempty skips it — should pass
		_, err := api.DecodeAndValidate[testDTO](req)
		assert.NoError(t, err)
	})

	t.Run("trailing JSON after object returns ValidationError", func(t *testing.T) {
		body := []byte(`{"name":"Alice","email":"alice@example.com"}{"extra":true}`)
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["body"])
	})

	t.Run("multiple missing fields returns multiple keys in details", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(`{}`)))

		_, err := api.DecodeAndValidate[testDTO](req)

		var valErr *domain.ValidationError
		assert.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["name"])
		assert.NotEmpty(t, valErr.Details()["email"])
	})
}

func TestDecodeAndValidate_flagKey(t *testing.T) {
	decode := func(t *testing.T, key string) error {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"key": key})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[flagKeyDTO](req)
		return err
	}

	for _, key := range []string{"beta", "new-dashboard", "2fa-login", "a", "v2-checkout-flow"} {
		t.Run("success - "+key, func(t *testing.T) {
			assert.NoError(t, decode(t, key))
		})
	}

	for _, key := range []string{"New-Dashboard", "-leading", "has space", "under_score", "dot.ted", "ação", ""} {
		t.Run("error - "+key, func(t *testing.T) {
			err := decode(t, key)

			var valErr *domain.ValidationError
			require.True(t, errors.As(err, &valErr))
			assert.Equal(t,
				"must contain only lowercase letters, digits and hyphens, and start with a letter or digit",
				valErr.Details()["key"],
			)
		})
	}

	t.Run("error - CreateFeatureFlagDTO rejects an invalid key", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"key": "Not Valid"})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		_, err := api.DecodeAndValidate[domain.CreateFeatureFlagDTO](req)

		var valErr *domain.ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.NotEmpty(t, valErr.Details()["key"])
	})

	t.Run("success - CreateFeatureFlagDTO accepts a kebab-case key", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"key": "new-dashboard"})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))

		dto, err := api.DecodeAndValidate[domain.CreateFeatureFlagDTO](req)

		require.NoError(t, err)
		assert.Equal(t, "new-dashboard", dto.Key)
	})
}

func TestGetClientMetadata(t *testing.T) {
	t.Run("prefers the client ip resolved into the request context data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		req = req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{ClientIP: "203.0.113.5"}))

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "203.0.113.5", ip)
	})

	t.Run("ignores X-Forwarded-For and X-Real-IP when no client ip was resolved", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		req.Header.Set("X-Forwarded-For", "203.0.113.5, 192.168.1.1")
		req.Header.Set("X-Real-IP", "198.51.100.7")
		req.Header.Set("User-Agent", "TestAgent/1.0")

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "10.0.0.1", ip)
		assert.Equal(t, "TestAgent/1.0", ua)
	})

	t.Run("returns RemoteAddr without the port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "10.0.0.1", ip)
		assert.Empty(t, ua)
	})

	t.Run("strips the port from an IPv4 RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.0.42:9999"

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "192.168.0.42", ip)
	})

	t.Run("returns RemoteAddr as-is when it has no port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.0.42"

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "192.168.0.42", ip)
	})
}
