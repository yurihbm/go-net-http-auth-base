package factories

import (
	"go-net-http-auth-base/internal/controllers"
)

func FeatureFlagsFactory(deps *Dependencies) controllers.Controller {
	return controllers.NewFeatureFlagsController(
		deps.FeatureFlagsService,
		deps.AuditService,
		deps.AuthMiddleware,
		deps.AdminRoleMiddleware,
	)
}
