package services_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"

	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
)

func TestGenerateOTP(t *testing.T) {
	t.Run("success - six numeric digits", func(t *testing.T) {
		for range 50 {
			code, err := services.GenerateOTP()

			assert.NoError(t, err)
			assert.Regexp(t, regexp.MustCompile(`^[0-9]{6}$`), code)
		}
	})
}

func TestHashOTP(t *testing.T) {
	key := []byte("secret")

	t.Run("success - deterministic", func(t *testing.T) {
		assert.Equal(t, services.HashOTP(key, "scope", "123456"), services.HashOTP(key, "scope", "123456"))
	})

	t.Run("success - different scope gives different hash", func(t *testing.T) {
		assert.NotEqual(t, services.HashOTP(key, "scope-a", "123456"), services.HashOTP(key, "scope-b", "123456"))
	})

	t.Run("success - equals hex HMAC of scope:code", func(t *testing.T) {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("scope:123456"))

		assert.Equal(t, hex.EncodeToString(mac.Sum(nil)), services.HashOTP(key, "scope", "123456"))
	})
}
