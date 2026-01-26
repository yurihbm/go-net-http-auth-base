package factories

import "go-net-http-auth-base/internal/middlewares"

func RequestUUIDFactory() middlewares.GlobalMiddleware {
	return middlewares.NewRequestUUIDMiddleware()
}
