package factories

import (
	"go-net-http-auth-base/internal/middlewares"
)

func RecoverFactory() middlewares.GlobalMiddleware {
	return middlewares.NewRecoverMiddleware()
}
