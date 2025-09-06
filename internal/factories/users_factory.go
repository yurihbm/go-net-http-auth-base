package factories

import (
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func UsersFactory(conn *pgx.Conn) *controllers.UsersController {
	userRepository := repositories.NewUsersPostgresRepository(conn)
	userServce := services.NewUserService(userRepository)
	return controllers.NewUsersController(userServce)
}
