package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/middlewares"
)

func CORSFactory(corsCfg config.CORSConfig) middlewares.GlobalMiddleware {
	allowedHeaders := []string{"Content-Type", "Authorization"}
	exposeHeaders := []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"}
	allowCredentials := true
	maxAge := "86400"

	return middlewares.NewCORSMiddleware(
		corsCfg.AllowedOrigins,
		corsCfg.AllowedMethods,
		allowedHeaders,
		exposeHeaders,
		allowCredentials,
		maxAge,
	)
}
