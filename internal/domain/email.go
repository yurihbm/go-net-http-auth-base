package domain

import "context"

type EmailMessage struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

type EmailProvider interface {
	Send(ctx context.Context, msg EmailMessage) error
}

type EmailChangeRevert struct {
	UserUUID  string
	OldEmail  string
	NewEmail  string
	Version   int
	ChangedAt int64
}

type EmailVerificationService interface {
	SendSignupCode(ctx context.Context, email string, code string) error
	SendOAuthSignupCode(ctx context.Context, email string, code string, provider OAuthProviderName) error
	SendEmailChangeCode(ctx context.Context, newEmail string, code string) error
	SendStepUpCode(ctx context.Context, email string, code string) error
	SendEmailChangedNotice(ctx context.Context, revert EmailChangeRevert) error
	VerifyEmailChangeRevertToken(ctx context.Context, token string) (*EmailChangeRevert, error)
}
