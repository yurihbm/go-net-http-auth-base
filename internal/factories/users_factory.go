package factories

import (
	"go-net-http-auth-base/internal/controllers"
)

func UsersFactory(deps *Dependencies) controllers.Controller {
	return controllers.NewUsersController(deps.UsersService, deps.AuditService, deps.AuthMiddleware)
}
