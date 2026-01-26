package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/providers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func UsersFactory(conn *pgx.Conn) controllers.Controller {
	userRepository := repositories.NewUsersPostgresRepository(conn)
	userService := services.NewUserService(userRepository)

	authRepository := repositories.NewAuthPostgresRepository(conn)
	oauthProviderRegistry, err := providers.NewOAuthProviderRegistry(
		map[domain.OAuthProviderName]domain.OAuthProvider{
			domain.OAuthProviderGoogle: providers.NewGoogleOAuthProvider(
				config.NewGoogleOAuthConfig(),
			),
			domain.OAuthProviderGitHub: providers.NewGitHubOAuthProvider(
				config.NewGitHubOAuthConfig(),
			),
			domain.OAuthProviderMicrosoft: providers.NewMicrosoftOAuthProvider(
				config.NewMicrosoftOAuthConfig(),
			),
		},
	)
	if err != nil {
		panic("failed to create OAuth provider registry: " + err.Error())
	}
	authService := services.NewAuthService(
		userService,
		authRepository,
		oauthProviderRegistry,
	)
	authMiddleware := middlewares.NewAuthMiddleware(authService)

	return controllers.NewUsersController(userService, authMiddleware)
}
