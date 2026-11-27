package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/middlewares"
)

func UsersFactory(deps *Dependencies, cfg *config.Config, credentialsLimiter middlewares.HandlerMiddleware) controllers.Controller {
	return controllers.NewUsersController(
		deps.UsersService,
		deps.EmailChangeService,
		deps.PendingSignupService,
		deps.PasswordService,
		deps.AuditService,
		deps.AuthMiddleware,
		deps.StepUpMiddleware,
		deps.AdminRoleMiddleware,
		credentialsLimiter,
		!cfg.IsDevelopment(),
	)
}
