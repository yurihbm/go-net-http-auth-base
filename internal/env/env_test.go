package env_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/internal/env"
)

func TestLookupFloat(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value, err := env.LookupFloat("NON_EXISTENT_ENV_VAR_FLOAT", 3.14)

		assert.NoError(t, err)
		assert.Equal(t, 3.14, value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_FLOAT", "2.71")

		value, err := env.LookupFloat("TEST_ENV_VAR_FLOAT", 3.14)

		assert.NoError(t, err)
		assert.Equal(t, 2.71, value)
	})

	t.Run("error - invalid value", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_FLOAT", "not-a-float")

		_, err := env.LookupFloat("TEST_ENV_VAR_FLOAT", 3.14)

		assert.ErrorContains(t, err, "TEST_ENV_VAR_FLOAT")
	})
}

func TestLookupInt(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value, err := env.LookupInt("NON_EXISTENT_ENV_VAR_INT", 42)

		assert.NoError(t, err)
		assert.Equal(t, 42, value)
	})

	t.Run("returns default when set to empty string", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT", "")

		value, err := env.LookupInt("TEST_ENV_VAR_INT", 42)

		assert.NoError(t, err)
		assert.Equal(t, 42, value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT", "7")

		value, err := env.LookupInt("TEST_ENV_VAR_INT", 42)

		assert.NoError(t, err)
		assert.Equal(t, 7, value)
	})

	t.Run("error - invalid value", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT", "not-an-int")

		_, err := env.LookupInt("TEST_ENV_VAR_INT", 42)

		assert.ErrorContains(t, err, "TEST_ENV_VAR_INT")
	})
}

func TestLookupInt32(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value, err := env.LookupInt32("NON_EXISTENT_ENV_VAR_INT32", 10)

		assert.NoError(t, err)
		assert.Equal(t, int32(10), value)
	})

	t.Run("returns default when set to empty string", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "")

		value, err := env.LookupInt32("TEST_ENV_VAR_INT32", 10)

		assert.NoError(t, err)
		assert.Equal(t, int32(10), value)
	})

	t.Run("error - value overflows int32", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "3000000000")

		_, err := env.LookupInt32("TEST_ENV_VAR_INT32", 10)

		assert.ErrorContains(t, err, "TEST_ENV_VAR_INT32")
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "99")

		value, err := env.LookupInt32("TEST_ENV_VAR_INT32", 10)

		assert.NoError(t, err)
		assert.Equal(t, int32(99), value)
	})

	t.Run("error - invalid value", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT32", "not-an-int32")

		_, err := env.LookupInt32("TEST_ENV_VAR_INT32", 10)

		assert.ErrorContains(t, err, "TEST_ENV_VAR_INT32")
	})
}

func TestLookupDuration(t *testing.T) {
	t.Run("returns default when not set", func(t *testing.T) {
		value, err := env.LookupDuration("NON_EXISTENT_ENV_VAR_DURATION", 5*time.Second)

		assert.NoError(t, err)
		assert.Equal(t, 5*time.Second, value)
	})

	t.Run("returns default when set to empty string", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_DURATION", "")

		value, err := env.LookupDuration("TEST_ENV_VAR_DURATION", 5*time.Second)

		assert.NoError(t, err)
		assert.Equal(t, 5*time.Second, value)
	})

	t.Run("returns parsed value when set", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_DURATION", "2m30s")

		value, err := env.LookupDuration("TEST_ENV_VAR_DURATION", 5*time.Second)

		assert.NoError(t, err)
		assert.Equal(t, 2*time.Minute+30*time.Second, value)
	})

	t.Run("error - invalid value", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_DURATION", "not-a-duration")

		_, err := env.LookupDuration("TEST_ENV_VAR_DURATION", 5*time.Second)

		assert.ErrorContains(t, err, "TEST_ENV_VAR_DURATION")
	})
}
