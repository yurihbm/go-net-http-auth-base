package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeEmail(t *testing.T) {
	assert.Equal(t, "user@example.com", normalizeEmail("  User@Example.COM "))
	assert.Equal(t, "", normalizeEmail("   "))
}
