package middlewares

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

func NewRateLimitMiddlewareWithClock(ctx context.Context, r rate.Limit, b int, now func() time.Time) GlobalMiddleware {
	return newRateLimitMiddleware(ctx, r, b, now)
}

func NewCredentialsRateLimitMiddlewareWithClock(ctx context.Context, perMinute float64, b int, now func() time.Time) HandlerMiddleware {
	return newCredentialsRateLimitMiddleware(ctx, perMinute, b, now)
}
