package domain

import "time"

const (
	EmailChangeCodeTTL     = 10 * time.Minute
	EmailChangeMaxAttempts = 5
	EmailChangeCooldown    = 60 * time.Second
)

var (
	ErrEmailChangeNoChallenge = NewUnauthorizedError("users.emailChange.noChallenge")
	ErrEmailChangeInvalidCode = NewUnauthorizedError("users.emailChange.invalidCode")
)
