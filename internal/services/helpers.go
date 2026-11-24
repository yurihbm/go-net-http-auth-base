package services

import (
	"strings"
	"unicode/utf8"
)

const (
	minDisplayNameRunes = 3
	maxDisplayNameRunes = 100
)

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Provider names bypass the DTO validation and may be empty or too long, so
// they are brought to the same 3 to 100 character bounds as a typed name.
func normalizeDisplayName(name, email string) string {
	name = truncateRunes(strings.TrimSpace(name), maxDisplayNameRunes)
	if utf8.RuneCountInString(name) >= minDisplayNameRunes {
		return name
	}
	localPart, _, _ := strings.Cut(email, "@")
	if utf8.RuneCountInString(localPart) >= minDisplayNameRunes {
		return truncateRunes(localPart, maxDisplayNameRunes)
	}
	return truncateRunes(email, maxDisplayNameRunes)
}

func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}
