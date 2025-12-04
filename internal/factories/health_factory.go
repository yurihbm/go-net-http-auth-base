package factories

import (
	"go-net-http-auth-base/internal/controllers"

	"github.com/jackc/pgx/v5"
)

func HealthFactory(db *pgx.Conn) controllers.Controller {
	return controllers.NewHealthController(db)
}
