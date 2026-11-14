package factories

import (
	"go-net-http-auth-base/internal/controllers"
)

func DocsFactory(deps *Dependencies) controllers.Controller {
	return controllers.NewDocsController(deps.AuthMiddleware, deps.AdminRoleMiddleware)
}
