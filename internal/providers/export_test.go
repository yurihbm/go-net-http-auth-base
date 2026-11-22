package providers

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"
)

func NewResendEmailProviderWithWait(apiKey, from, baseURL string, wait func(ctx context.Context, d time.Duration) error) domain.EmailProvider {
	p := NewResendEmailProvider(apiKey, from, baseURL).(*resendEmailProvider)
	p.wait = wait
	return p
}

func NewResendEmailProviderWithTotalTimeout(apiKey, from, baseURL string, total time.Duration) domain.EmailProvider {
	p := NewResendEmailProvider(apiKey, from, baseURL).(*resendEmailProvider)
	p.totalTimeout = total
	return p
}
