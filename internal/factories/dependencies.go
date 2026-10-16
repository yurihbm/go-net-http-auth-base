package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/providers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Dependencies struct {
	Pool *pgxpool.Pool

	UsersService domain.UsersService
	AuthService  domain.AuthService
	AuditService domain.AuditService

	EmailProvider domain.EmailProvider

	AuthMiddleware      middlewares.HandlerMiddleware
	AdminRoleMiddleware middlewares.HandlerMiddleware
}

func NewDependencies(pool *pgxpool.Pool, cfg *config.Config) (*Dependencies, error) {
	db := repositories.NewTxAwareDB(pool)

	tokenService := services.NewTokenService(cfg.JWTSecret)
	emailProvider := newEmailProvider(cfg.Email)
	emailVerificationService := services.NewEmailVerificationService(tokenService, emailProvider, cfg.Email.VerificationURL)

	usersRepository := repositories.NewUsersPostgresRepository(db)
	usersService := services.NewUserService(usersRepository, emailVerificationService)

	authRepository := repositories.NewAuthPostgresRepository(db)
	oauthProviderRegistry, err := providers.NewOAuthProviderRegistry(
		map[domain.OAuthProviderName]domain.OAuthProvider{
			domain.OAuthProviderGoogle: providers.NewGoogleOAuthProvider(
				config.NewGoogleOAuthConfig(cfg.OAuth.Google, cfg.APIURL),
			),
			domain.OAuthProviderGitHub: providers.NewGitHubOAuthProvider(
				config.NewGitHubOAuthConfig(cfg.OAuth.GitHub, cfg.APIURL),
			),
			domain.OAuthProviderMicrosoft: providers.NewMicrosoftOAuthProvider(
				config.NewMicrosoftOAuthConfig(cfg.OAuth.Microsoft, cfg.APIURL),
			),
		},
	)
	if err != nil {
		return nil, err
	}
	authService := services.NewAuthService(
		usersService,
		authRepository,
		oauthProviderRegistry,
		repositories.NewPostgresTransactor(pool),
		tokenService,
	)

	auditRepository := repositories.NewAuditPostgresRepository(db)
	auditService := services.NewAuditService(auditRepository)

	return &Dependencies{
		Pool:                pool,
		UsersService:        usersService,
		AuthService:         authService,
		AuditService:        auditService,
		EmailProvider:       emailProvider,
		AuthMiddleware:      middlewares.NewAuthMiddleware(authService),
		AdminRoleMiddleware: middlewares.NewRoleMiddleware([]domain.UserRole{domain.RoleAdmin}),
	}, nil
}

func newEmailProvider(cfg config.EmailConfig) domain.EmailProvider {
	if cfg.ResendAPIKey == "" {
		return providers.NewLogEmailProvider()
	}
	return providers.NewResendEmailProvider(cfg.ResendAPIKey, cfg.From)
}
