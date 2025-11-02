package factories

import (
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func UsersFactory(conn *pgx.Conn) *controllers.UsersController {
	userRepository := repositories.NewUsersPostgresRepository(conn)
	userService := services.NewUserService(userRepository)

	authRepository := repositories.NewAuthPostgresRepository(conn)
	authService := services.NewAuthService(userService, authRepository)
	authMiddleware := middlewares.NewAuthMiddleware(authService)

	return controllers.NewUsersController(userService, authMiddleware)
}
