package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
)

func AuthFactory(deps *Dependencies, cfg *config.Config) controllers.Controller {
	return controllers.NewAuthController(
		deps.AuthService,
		deps.UsersService,
		deps.AuditService,
		!cfg.IsDevelopment(),
	)
}
