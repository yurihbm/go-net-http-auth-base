package factories

import (
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func AuditFactory(conn *pgx.Conn) controllers.Controller {
	auditRepository := repositories.NewAuditPostgresRepository(conn)
	auditService := services.NewAuditService(auditRepository)

	userRepository := repositories.NewUsersPostgresRepository(conn)
	userService := services.NewUserService(userRepository)

	authRepository := repositories.NewAuthPostgresRepository(conn)
	// nil OAuthProviderRegistry is safe here: AuditFactory only needs JWT
	// verification (VerifyToken), which does not use OAuth providers.
	authService := services.NewAuthService(userService, authRepository, nil)
	authMiddleware := middlewares.NewAuthMiddleware(authService)

	roleMiddleware := middlewares.NewRoleMiddleware(userService, []domain.UserRole{domain.RoleAdmin})

	return controllers.NewAuditController(auditService, authMiddleware, roleMiddleware)
}
