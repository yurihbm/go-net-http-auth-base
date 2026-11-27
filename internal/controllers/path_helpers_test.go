package controllers

import (
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
)

func TestPathUUID(t *testing.T) {
	const canonical = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

	newRequest := func(value string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.SetPathValue("uuid", value)
		return req
	}

	forms := map[string]string{
		"canonical": canonical,
		"uppercase": "0190A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B",
		"no-hyphen": "0190a1b2c3d47e5f8a9b0c1d2e3f4a5b",
		"braces":    "{" + canonical + "}",
		"urn":       "urn:uuid:" + canonical,
	}
	for name, value := range forms {
		t.Run("success - "+name+" returns the canonical form", func(t *testing.T) {
			got, err := pathUUID(newRequest(value), "uuid", "things.invalidUUID")

			assert.NoError(t, err)
			assert.Equal(t, canonical, got)
		})
	}

	t.Run("error - invalid UUID", func(t *testing.T) {
		got, err := pathUUID(newRequest("not-a-uuid"), "uuid", "things.invalidUUID")

		var validationErr *domain.ValidationError
		assert.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "things.invalidUUID", validationErr.Error())
		assert.Contains(t, validationErr.Details(), "uuid")
		assert.Empty(t, got)
	})
}
