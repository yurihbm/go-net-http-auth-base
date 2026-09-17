package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/middlewares"
)

func CORSFactory(corsCfg config.CORSConfig) middlewares.GlobalMiddleware {
	allowedHeaders := []string{"Content-Type", "Authorization"}
	exposeHeaders := []string{}
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
