package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
)

func UsersFactory(deps *Dependencies, cfg *config.Config) controllers.Controller {
	return controllers.NewUsersController(
		deps.UsersService,
		deps.EmailChangeService,
		deps.PendingSignupService,
		deps.PasswordService,
		deps.AuditService,
		deps.AuthMiddleware,
		deps.StepUpMiddleware,
		!cfg.IsDevelopment(),
	)
}
