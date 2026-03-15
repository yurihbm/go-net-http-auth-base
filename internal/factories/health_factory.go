package factories

import (
	"go-net-http-auth-base/internal/controllers"

	"github.com/jackc/pgx/v5/pgxpool"
)

func HealthFactory(db *pgxpool.Pool) controllers.Controller {
	return controllers.NewHealthController(db)
}
