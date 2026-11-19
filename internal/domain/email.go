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

type EmailChange struct {
	UserUUID     string
	CurrentEmail string
	NewEmail     string
	Version      int
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
	SendEmailChangeEmail(ctx context.Context, user *User, newEmail string) error
	VerifyEmailChangeToken(ctx context.Context, token string) (*EmailChange, error)
	SendStepUpCode(ctx context.Context, email string, code string) error
	SendEmailChangedNotice(ctx context.Context, revert EmailChangeRevert) error
	VerifyEmailChangeRevertToken(ctx context.Context, token string) (*EmailChangeRevert, error)
}
