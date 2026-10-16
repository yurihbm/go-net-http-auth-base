package providers

import (
	"context"
	"log/slog"

	"go-net-http-auth-base/internal/domain"
)

type logEmailProvider struct{}

func NewLogEmailProvider() domain.EmailProvider {
	return &logEmailProvider{}
}

func (p *logEmailProvider) Send(ctx context.Context, msg domain.EmailMessage) error {
	slog.InfoContext(ctx, "email not sent, logging instead",
		"to", msg.To,
		"subject", msg.Subject,
		"text", msg.Text,
		"html", msg.HTML,
	)
	return nil
}
