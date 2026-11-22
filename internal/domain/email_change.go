package domain

import (
	"context"
	"time"
)

const (
	EmailChangeCodeTTL     = 10 * time.Minute
	EmailChangeMaxAttempts = 5
	EmailChangeCooldown    = 60 * time.Second
	EmailChangeLock        = 72 * time.Hour
)

var (
	ErrEmailChangeNoChallenge = NewUnauthorizedError("users.emailChange.noChallenge")
	ErrEmailChangeInvalidCode = NewUnauthorizedError("users.emailChange.invalidCode")
)

type EmailChangeService interface {
	RequestEmailChange(ctx context.Context, actor Actor, sessionUUID string, email string) error
	ConfirmEmailChange(ctx context.Context, actor Actor, sessionUUID string, code string) (*User, error)
	RevertEmailChange(context.Context, string) (*User, error)
}
