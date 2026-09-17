package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/middlewares"

	"golang.org/x/time/rate"
)

func RateLimitFactory(rlCfg config.RateLimitConfig) middlewares.GlobalMiddleware {
	return middlewares.NewRateLimitMiddleware(rate.Limit(rlCfg.RequestsPerSecond), rlCfg.Burst)
}
