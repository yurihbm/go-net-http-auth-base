package providers

import (
	"context"
	"log/slog"

	"go-net-http-auth-base/internal/domain"
)

type logEmailProvider struct {
	logBody bool
}

func NewLogEmailProvider(logBody bool) domain.EmailProvider {
	return &logEmailProvider{logBody: logBody}
}

func (p *logEmailProvider) Send(ctx context.Context, msg domain.EmailMessage) error {
	attrs := []any{"to", msg.To, "subject", msg.Subject}
	if p.logBody {
		attrs = append(attrs, "text", msg.Text)
	}
	slog.InfoContext(ctx, "email not sent, logging instead", attrs...)
	return nil
}
