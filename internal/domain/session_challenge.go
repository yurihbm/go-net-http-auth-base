package domain

import (
	"context"
	"time"
)

type SessionChallengePurpose string

const (
	SessionChallengeStepUp      SessionChallengePurpose = "step_up"
	SessionChallengeEmailChange SessionChallengePurpose = "email_change"
)

type SessionChallenge struct {
	UserUUID     string
	SessionUUID  string
	Purpose      SessionChallengePurpose
	NewEmail     string
	EmailVersion int
	CodeHash     string
	ExpiresAt    int64
}

type SessionChallengeRepository interface {
	Upsert(ctx context.Context, challenge SessionChallenge, cooldown time.Duration) error
	Find(ctx context.Context, userUUID string, sessionUUID string, purpose SessionChallengePurpose) (*SessionChallenge, error)
	Attempt(ctx context.Context, userUUID string, sessionUUID string, purpose SessionChallengePurpose, maxAttempts int) (*SessionChallenge, error)
	Delete(ctx context.Context, sessionUUID string, purpose SessionChallengePurpose) error
}
