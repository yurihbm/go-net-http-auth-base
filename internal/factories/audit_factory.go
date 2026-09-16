package factories

import (
	"go-net-http-auth-base/internal/controllers"
)

func AuditFactory(deps *Dependencies) controllers.Controller {
	return controllers.NewAuditController(deps.AuditService, deps.AuthMiddleware, deps.AdminRoleMiddleware)
}
