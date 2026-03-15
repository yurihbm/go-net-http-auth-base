package env_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/internal/env"
)

func TestGetEnvAsFloat(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value := env.GetEnvAsFloat("NON_EXISTENT_ENV_VAR_FLOAT", 3.14)

		assert.Equal(t, 3.14, value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_FLOAT", "2.71")

		value := env.GetEnvAsFloat("TEST_ENV_VAR_FLOAT", 3.14)

		assert.Equal(t, 2.71, value)
	})

	t.Run("returns default when value is invalid", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_FLOAT", "not-a-float")

		value := env.GetEnvAsFloat("TEST_ENV_VAR_FLOAT", 3.14)

		assert.Equal(t, 3.14, value)
	})
}

func TestGetEnvAsInt(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value := env.GetEnvAsInt("NON_EXISTENT_ENV_VAR_INT", 42)

		assert.Equal(t, 42, value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT", "7")

		value := env.GetEnvAsInt("TEST_ENV_VAR_INT", 42)

		assert.Equal(t, 7, value)
	})

	t.Run("returns default when value is invalid", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT", "not-an-int")

		value := env.GetEnvAsInt("TEST_ENV_VAR_INT", 42)

		assert.Equal(t, 42, value)
	})
}

func TestGetEnvAsInt32(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value := env.GetEnvAsInt32("NON_EXISTENT_ENV_VAR_INT32", 10)

		assert.Equal(t, int32(10), value)
	})

	t.Run("returns default when set to empty string", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "")

		value := env.GetEnvAsInt32("TEST_ENV_VAR_INT32", 10)

		assert.Equal(t, int32(10), value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "99")

		value := env.GetEnvAsInt32("TEST_ENV_VAR_INT32", 10)

		assert.Equal(t, int32(99), value)
	})

	t.Run("returns default when value is invalid", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "not-an-int32")

		value := env.GetEnvAsInt32("TEST_ENV_VAR_INT32", 10)

		assert.Equal(t, int32(10), value)
	})
}

func TestGetEnvAsDuration(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value := env.GetEnvAsDuration("NON_EXISTENT_ENV_VAR_DURATION", 5*time.Second)

		assert.Equal(t, 5*time.Second, value)
	})

	t.Run("returns default when set to empty string", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_DURATION", "")

		value := env.GetEnvAsDuration("TEST_ENV_VAR_DURATION", 5*time.Second)

		assert.Equal(t, 5*time.Second, value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_DURATION", "2m30s")

		value := env.GetEnvAsDuration("TEST_ENV_VAR_DURATION", 5*time.Second)

		assert.Equal(t, 2*time.Minute+30*time.Second, value)
	})

	t.Run("returns default when value is invalid", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_DURATION", "not-a-duration")

		value := env.GetEnvAsDuration("TEST_ENV_VAR_DURATION", 5*time.Second)

		assert.Equal(t, 5*time.Second, value)
	})
}
