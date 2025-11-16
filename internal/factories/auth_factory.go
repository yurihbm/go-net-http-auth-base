package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/providers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5"
)

func AuthFactory(conn *pgx.Conn) *controllers.AuthController {
	userRepository := repositories.NewUsersPostgresRepository(conn)
	userService := services.NewUserService(userRepository)

	authRepository := repositories.NewAuthPostgresRepository(conn)
	authService := services.NewAuthService(userService, authRepository)

	oauthProviders := map[domain.OAuthProviderName]domain.OAuthProvider{
		domain.OAuthProviderGoogle: providers.NewGoogleOAuthProvider(
			config.NewGoogleOAuthConfig(),
		),
		domain.OAuthProviderGitHub: providers.NewGitHubOAuthProvider(
			config.NewGitHubOAuthConfig(),
		),
		domain.OAuthProviderMicrosoft: providers.NewMicrosoftOAuthProvider(
			config.NewMicrosoftOAuthConfig(),
		),
	}

	return controllers.NewAuthController(
		authService,
		userService,
		oauthProviders,
	)
}
