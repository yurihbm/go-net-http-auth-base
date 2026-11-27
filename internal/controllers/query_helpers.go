package controllers

import (
	"net/url"
	"strconv"

	"go-net-http-auth-base/internal/domain"
)

func parseLimit(q url.Values, defaultLimit int, errorKey string) (int, error) {
	v := q.Get("limit")
	if v == "" {
		return defaultLimit, nil
	}
	limit, err := strconv.Atoi(v)
	if err != nil || limit < 1 || limit > 100 {
		return 0, domain.NewValidationError(errorKey, map[string]string{
			"limit": "limit must be an integer between 1 and 100",
		})
	}
	return limit, nil
}
