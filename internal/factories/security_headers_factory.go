package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/middlewares"
)

func SecurityHeadersFactory(cfg *config.Config) middlewares.GlobalMiddleware {
	return middlewares.NewSecurityHeadersMiddleware(!cfg.IsDevelopment())
}
