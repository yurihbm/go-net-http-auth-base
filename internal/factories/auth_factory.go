package factories

import (
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func AuthFactory(conn *pgx.Conn) *controllers.AuthController {
	userRepository := repositories.NewUsersPostgresRepository(conn)
	userService := services.NewUserService(userRepository)
	authService := services.NewAuthService(userService)
	return controllers.NewAuthController(authService)
}
