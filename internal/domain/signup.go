package domain

import (
	"context"
	"time"
)

const (
	SignupCodeTTL          = 10 * time.Minute
	PendingSignupTTL       = time.Hour
	SignupMaxAttempts      = 5
	EmailSendCooldown      = 60 * time.Second
	EmailSendWindow        = time.Hour
	EmailMaxSendsPerWindow = 5
	EmailCodeFailureWindow = 24 * time.Hour
	EmailMaxCodeFailures   = 20
)

var (
	ErrSignupNoPending   = NewUnauthorizedError("auth.signup.noPending")
	ErrSignupInvalidCode = NewUnauthorizedError("auth.signup.invalidCode")
	ErrEmailSendLimit    = NewTooManyRequestsError("auth.email.sendLimit")
	ErrEmailCodeLocked   = NewTooManyRequestsError("auth.email.codeLocked")
)

type PendingSignupKind string

const (
	PendingSignupKindCredentials PendingSignupKind = "credentials"
	PendingSignupKindOAuth       PendingSignupKind = "oauth"
)

type PendingSignup struct {
	UUID           string
	Kind           PendingSignupKind
	Name           string
	Email          string
	PasswordHash   string
	Provider       OAuthProviderName
	ProviderUserID string
	CodeHash       string
	Attempts       int
	CodeExpiresAt  int64
	ExpiresAt      int64
	CreatedAt      int64
}

type StartOAuthSignupDTO struct {
	Name           string
	Email          string
	Provider       OAuthProviderName
	ProviderUserID string
}

type SignupVerifyDTO struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

type SignupResult struct {
	User   *User
	Tokens AuthTokens
}

type PendingSignupRepository interface {
	Create(ctx context.Context, pending PendingSignup) (*PendingSignup, error)
	FindByUUID(ctx context.Context, uuid string) (*PendingSignup, error)
	Attempt(ctx context.Context, uuid string, maxAttempts int) (*PendingSignup, error)
	Consume(ctx context.Context, uuid string, codeHash string) (*PendingSignup, error)
	Resend(ctx context.Context, uuid string, codeHash string, codeTTL time.Duration) (*PendingSignup, error)
	Delete(ctx context.Context, uuid string) error
}

type EmailSendLimiter interface {
	ReserveSend(ctx context.Context, email string, cooldown time.Duration, window time.Duration, maxSends int) error
	ReserveCodeGuess(ctx context.Context, email string, window time.Duration) error
	RefundCodeGuess(ctx context.Context, email string) error
}

type PendingSignupService interface {
	StartCredentials(ctx context.Context, dto CreateUserDTO) (string, error)
	StartOAuth(ctx context.Context, dto StartOAuthSignupDTO) (string, error)
	Resend(ctx context.Context, pendingUUID string) error
	Attempt(ctx context.Context, pendingUUID string, code string) error
	Consume(ctx context.Context, pendingUUID string, code string) (*PendingSignup, error)
}
