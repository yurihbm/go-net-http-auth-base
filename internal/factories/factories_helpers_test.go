package factories_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/internal/factories"
)

func TestGetEnvAsFloat(t *testing.T) {
	t.Run("default value", func(t *testing.T) {
		value := factories.GetEnvAsFloat("NON_EXISTENT_ENV_VAR_FLOAT", 3.14)

		assert.Equal(t, 3.14, value)
	})

	t.Run("set value", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_FLOAT", "2.71")

		value := factories.GetEnvAsFloat("TEST_ENV_VAR_FLOAT", 3.14)

		assert.Equal(t, 2.71, value)
	})
}

func TestGetEnvAsInt(t *testing.T) {
	t.Run("default value", func(t *testing.T) {
		value := factories.GetEnvAsInt("NON_EXISTENT_ENV_VAR_INT", 42)

		assert.Equal(t, 42, value)
	})

	t.Run("set value", func(t *testing.T) {
		t.Setenv("TEST_ENV_VAR_INT", "7")

		value := factories.GetEnvAsInt("TEST_ENV_VAR_INT", 42)

		assert.Equal(t, 7, value)
	})
}
