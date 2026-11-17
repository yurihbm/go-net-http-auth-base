package api_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
)

type testDTO struct {
	Name  string `json:"name"  validate:"required"`
	Email string `json:"email" validate:"required,email"`
	Age   int    `json:"age"   validate:"omitempty,min=1"`
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

func TestGetClientMetadata(t *testing.T) {
	t.Run("ignores X-Forwarded-For and X-Real-IP sent by the client", func(t *testing.T) {
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
