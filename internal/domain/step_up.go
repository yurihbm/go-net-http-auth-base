package domain

import (
	"context"
	"time"
)

const (
	StepUpCodeTTL            = 10 * time.Minute
	StepUpElevationWindow    = 5 * time.Minute
	StepUpMaxAttempts        = 5
	StepUpMaxSessionFailures = 10
	StepUpMaxUserFailures    = 20
	StepUpUserFailureWindow  = 24 * time.Hour
	StepUpCooldown           = 60 * time.Second
	EmailChangeLock          = 72 * time.Hour
)

var ErrStepUpSessionRevoked = NewUnauthorizedError("auth.stepUp.sessionRevoked")

type StepUpChallenge struct {
	UserUUID    string
	SessionUUID string
	CodeHash    string
	Attempts    int
	ExpiresAt   int64
	CreatedAt   int64
}

type StepUpVerifyDTO struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

type StepUpRepository interface {
	Upsert(ctx context.Context, challenge StepUpChallenge, cooldown time.Duration) (*StepUpChallenge, error)
	Attempt(ctx context.Context, userUUID string, sessionUUID string, maxAttempts int) (*StepUpChallenge, error)
	Delete(ctx context.Context, sessionUUID string) error
}

type StepUpChecker interface {
	IsElevated(ctx context.Context, userUUID string, sessionUUID string) (bool, error)
}

type StepUpService interface {
	StepUpChecker
	RequestCode(ctx context.Context, userUUID string, sessionUUID string) error
	VerifyCode(ctx context.Context, userUUID string, sessionUUID string, code string) (int64, error)
}
