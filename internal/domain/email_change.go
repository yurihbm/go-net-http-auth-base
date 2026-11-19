package domain

import (
	"context"
	"time"
)

const (
	EmailChangeCodeTTL     = 10 * time.Minute
	EmailChangeMaxAttempts = 5
	EmailChangeCooldown    = 60 * time.Second
)

var (
	ErrEmailChangeNoChallenge = NewUnauthorizedError("users.emailChange.noChallenge")
	ErrEmailChangeInvalidCode = NewUnauthorizedError("users.emailChange.invalidCode")
)

type EmailChangeChallenge struct {
	UserUUID     string
	SessionUUID  string
	NewEmail     string
	EmailVersion int
	CodeHash     string
	Attempts     int
	ExpiresAt    int64
	CreatedAt    int64
}

type EmailChangeRepository interface {
	Upsert(ctx context.Context, challenge EmailChangeChallenge, cooldown time.Duration) (*EmailChangeChallenge, error)
	Attempt(ctx context.Context, userUUID string, sessionUUID string, maxAttempts int) (*EmailChangeChallenge, error)
	Delete(ctx context.Context, sessionUUID string) error
}
