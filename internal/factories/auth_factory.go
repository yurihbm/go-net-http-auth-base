package factories

import (
	"go-net-http-auth-base/internal/controllers"
)

func AuthFactory(deps *Dependencies) controllers.Controller {
	return controllers.NewAuthController(
		deps.AuthService,
		deps.UsersService,
		deps.AuditService,
	)
}
