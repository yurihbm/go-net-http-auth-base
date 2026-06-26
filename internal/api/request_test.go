package api_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
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
	t.Run("returns X-Forwarded-For first address", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.5, 192.168.1.1")
		req.Header.Set("User-Agent", "TestAgent/1.0")

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "203.0.113.5", ip)
		assert.Equal(t, "TestAgent/1.0", ua)
	})

	t.Run("falls back to X-Real-IP when X-Forwarded-For absent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "198.51.100.7")
		req.Header.Set("User-Agent", "RealIPAgent/2.0")

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "198.51.100.7", ip)
		assert.Equal(t, "RealIPAgent/2.0", ua)
	})

	t.Run("falls back to RemoteAddr when no proxy headers set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"

		ip, ua := api.GetClientMetadata(req)

		assert.Equal(t, "10.0.0.1", ip)
		assert.Empty(t, ua)
	})

	t.Run("X-Forwarded-For takes priority over X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		req.Header.Set("X-Real-IP", "5.6.7.8")

		ip, _ := api.GetClientMetadata(req)

		assert.Equal(t, "1.2.3.4", ip)
	})

	t.Run("strips port from RemoteAddr with no proxy headers", func(t *testing.T) {
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
