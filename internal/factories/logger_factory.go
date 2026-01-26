package factories

import (
	"go-net-http-auth-base/internal/middlewares"
)

func LoggerFactory() middlewares.GlobalMiddleware {
	return middlewares.NewLoggerMiddleware()
}
