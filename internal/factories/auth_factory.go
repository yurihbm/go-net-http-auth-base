package factories

import (
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func AuthFactory(conn *pgx.Conn) *controllers.AuthController {
	userRepository := repositories.NewUsersPostgresRepository(conn)
	authService := services.NewAuthService(userRepository)
	return controllers.NewAuthController(authService)
}
