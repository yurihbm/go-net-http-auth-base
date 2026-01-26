package factories

import "go-net-http-auth-base/internal/middlewares"

func RequestContextDataFactory() *middlewares.RequestContextDataMiddleware {
	return middlewares.NewRequestContextDataMiddleware()
}
