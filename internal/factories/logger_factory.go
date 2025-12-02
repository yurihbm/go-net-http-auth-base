package factories

import (
	"go-net-http-auth-base/internal/middlewares"
)

func LoggerFactory() *middlewares.LoggerMiddleware {
	return middlewares.NewLoggerMiddleware()
}
