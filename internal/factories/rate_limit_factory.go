package factories

import (
	"go-net-http-auth-base/internal/middlewares"

	"golang.org/x/time/rate"
)

func RateLimitFactory() *middlewares.RateLimitMiddleware {
	rps := GetEnvAsFloat("RATE_LIMIT_REQUESTS_PER_SECOND", 20.0)
	burst := GetEnvAsInt("RATE_LIMIT_BURST", 50)

	return middlewares.NewRateLimitMiddleware(rate.Limit(rps), burst)
}
