package controllers

import (
	"net/url"
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLimit(t *testing.T) {
	t.Run("success - absent returns the default", func(t *testing.T) {
		got, err := parseLimit(url.Values{}, 20, "things.list.badRequest")

		require.NoError(t, err)
		assert.Equal(t, 20, got)
	})

	for value, want := range map[string]int{"1": 1, "50": 50, "100": 100} {
		t.Run("success - "+value, func(t *testing.T) {
			got, err := parseLimit(url.Values{"limit": {value}}, 20, "things.list.badRequest")

			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}

	for _, value := range []string{"abc", "0", "-1", "101"} {
		t.Run("error - "+value, func(t *testing.T) {
			_, err := parseLimit(url.Values{"limit": {value}}, 20, "things.list.badRequest")

			var validationErr *domain.ValidationError
			require.ErrorAs(t, err, &validationErr)
			assert.Equal(t, "things.list.badRequest", validationErr.Error())
		})
	}
}
