package middlewares

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

type CredentialsRateLimitMiddleware struct {
	limiter *RateLimitMiddleware
}

func NewCredentialsRateLimitMiddleware(ctx context.Context, perMinute float64, burst int) HandlerMiddleware {
	return newCredentialsRateLimitMiddleware(ctx, perMinute, burst, time.Now)
}

func newCredentialsRateLimitMiddleware(ctx context.Context, perMinute float64, burst int, now func() time.Time) HandlerMiddleware {
	return &CredentialsRateLimitMiddleware{
		limiter: newRateLimitMiddleware(ctx, rate.Limit(perMinute/60), burst, now).(*RateLimitMiddleware),
	}
}

func (m *CredentialsRateLimitMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.limiter.allow(w, r) {
			next(w, r)
		}
	}
}
