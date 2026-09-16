package factories

import (
	"go-net-http-auth-base/internal/controllers"
)

func HealthFactory(deps *Dependencies) controllers.Controller {
	return controllers.NewHealthController(deps.Pool)
}
