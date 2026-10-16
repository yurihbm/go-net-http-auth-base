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

type EmailVerificationService interface {
	SendVerificationEmail(ctx context.Context, user *User) error
	VerifyVerificationToken(ctx context.Context, token string) (string, error)
}
