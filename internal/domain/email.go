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
}

type EmailVerificationService interface {
	SendVerificationEmail(ctx context.Context, user *User) error
	VerifyVerificationToken(ctx context.Context, token string) (string, error)
	SendEmailChangeEmail(ctx context.Context, user *User, newEmail string) error
	VerifyEmailChangeToken(ctx context.Context, token string) (*EmailChange, error)
	SendStepUpCode(ctx context.Context, email string, code string) error
	SendEmailChangedNotice(ctx context.Context, oldEmail string, newEmail string) error
}
