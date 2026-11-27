package domain_test

import (
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPage(t *testing.T) {
	cursorOf := func(s string) string { return s }

	t.Run("success - more items than limit are trimmed and cursor is the last kept item", func(t *testing.T) {
		page := domain.NewPage([]string{"a", "b", "c"}, 9, 2, cursorOf)

		assert.Equal(t, []string{"a", "b"}, page.Items)
		require.NotNil(t, page.NextCursor)
		assert.Equal(t, "b", *page.NextCursor)
		assert.Equal(t, int64(9), page.Total)
	})

	t.Run("success - exactly limit items have no cursor", func(t *testing.T) {
		page := domain.NewPage([]string{"a", "b"}, 9, 2, cursorOf)

		assert.Equal(t, []string{"a", "b"}, page.Items)
		assert.Nil(t, page.NextCursor)
	})

	t.Run("success - no items have no cursor", func(t *testing.T) {
		page := domain.NewPage([]string{}, 0, 2, cursorOf)

		assert.Empty(t, page.Items)
		assert.Nil(t, page.NextCursor)
	})
}
