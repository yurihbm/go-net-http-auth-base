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
)

var (
	ErrStepUpNoChallenge    = NewUnauthorizedError("auth.stepUp.noChallenge")
	ErrStepUpSessionRevoked = NewUnauthorizedError("auth.stepUp.sessionRevoked")
	ErrStepUpUserLocked     = NewTooManyRequestsError("auth.stepUp.userLocked")
)

type StepUpChecker interface {
	IsElevated(ctx context.Context, userUUID string, sessionUUID string) (bool, error)
}

type StepUpService interface {
	StepUpChecker
	RequestCode(ctx context.Context, userUUID string, sessionUUID string) error
	VerifyCode(ctx context.Context, userUUID string, sessionUUID string, code string) (int64, error)
}
