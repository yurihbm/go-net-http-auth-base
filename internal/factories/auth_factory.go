package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/middlewares"
)

func AuthFactory(deps *Dependencies, cfg *config.Config, credentialsLimiter middlewares.HandlerMiddleware) controllers.Controller {
	return controllers.NewAuthController(
		deps.AuthService,
		deps.StepUpService,
		deps.PendingSignupService,
		deps.PasswordService,
		deps.AuditService,
		deps.AuthMiddleware,
		credentialsLimiter,
		!cfg.IsDevelopment(),
		cfg.OAuth.CallbackAllowList,
	)
}
