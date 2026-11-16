package factories

import (
	"context"
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/middlewares"

	"golang.org/x/time/rate"
)

func RateLimitFactory(ctx context.Context, rlCfg config.RateLimitConfig) middlewares.GlobalMiddleware {
	return middlewares.NewRateLimitMiddleware(ctx, rate.Limit(rlCfg.RequestsPerSecond), rlCfg.Burst)
}
