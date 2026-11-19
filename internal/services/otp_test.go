package services_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSendOrRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("success - no rollback", func(t *testing.T) {
		rolledBack := false

		err := services.SendOrRollback(ctx, "flow.sendFailed",
			func() error { return nil },
			func() error { rolledBack = true; return nil },
		)

		assert.NoError(t, err)
		assert.False(t, rolledBack)
	})

	t.Run("error - send failure rolls back", func(t *testing.T) {
		sendErr := errors.New("smtp down")
		rolledBack := false

		err := services.SendOrRollback(ctx, "flow.sendFailed",
			func() error { return sendErr },
			func() error { rolledBack = true; return nil },
		)

		var internal *domain.InternalServerError
		require.ErrorAs(t, err, &internal)
		assert.Equal(t, "flow.sendFailed", internal.Error())
		assert.ErrorIs(t, err, sendErr)
		assert.True(t, rolledBack)
	})

	t.Run("error - failing rollback still returns the send error", func(t *testing.T) {
		err := services.SendOrRollback(ctx, "flow.sendFailed",
			func() error { return errors.New("smtp down") },
			func() error { return errors.New("db down") },
		)

		assert.Equal(t, "flow.sendFailed", err.Error())
	})
}
