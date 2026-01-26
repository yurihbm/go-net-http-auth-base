package factories

import "go-net-http-auth-base/internal/middlewares"

func RequestContextDataFactory() middlewares.GlobalMiddleware {
	return middlewares.NewRequestContextDataMiddleware()
}
