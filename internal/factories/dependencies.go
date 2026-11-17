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

	UsersService  domain.UsersService
	AuthService   domain.AuthService
	AuditService  domain.AuditService
	StepUpService domain.StepUpService

	EmailProvider domain.EmailProvider

	AuthMiddleware      middlewares.HandlerMiddleware
	StepUpMiddleware    middlewares.HandlerMiddleware
	AdminRoleMiddleware middlewares.HandlerMiddleware
}

func NewDependencies(pool *pgxpool.Pool, cfg *config.Config) (*Dependencies, error) {
	db := repositories.NewTxAwareDB(pool)

	tokenService := services.NewTokenService(cfg.JWTSecret)
	emailProvider := newEmailProvider(cfg.Email)
	emailVerificationService := services.NewEmailVerificationService(tokenService, emailProvider, cfg.Email.VerificationURL, cfg.Email.ChangeURL, cfg.Email.ChangeRevertURL)

	usersRepository := repositories.NewUsersPostgresRepository(db)
	authRepository := repositories.NewAuthPostgresRepository(db)
	sessionsRepository := repositories.NewSessionsPostgresRepository(db)
	transactor := repositories.NewPostgresTransactor(pool)
	usersService := services.NewUserService(usersRepository, emailVerificationService, sessionsRepository, authRepository, transactor)
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
		sessionsRepository,
		oauthProviderRegistry,
		transactor,
		tokenService,
		cfg.SessionMaxAge,
		cfg.MaxSessionsPerUser,
	)

	stepUpService := services.NewStepUpService(
		repositories.NewStepUpPostgresRepository(db),
		sessionsRepository,
		usersRepository,
		transactor,
		emailVerificationService,
		[]byte(cfg.JWTSecret),
	)

	auditRepository := repositories.NewAuditPostgresRepository(db)
	auditService := services.NewAuditService(auditRepository)

	return &Dependencies{
		Pool:                pool,
		UsersService:        usersService,
		AuthService:         authService,
		AuditService:        auditService,
		StepUpService:       stepUpService,
		EmailProvider:       emailProvider,
		AuthMiddleware:      middlewares.NewAuthMiddleware(authService),
		StepUpMiddleware:    middlewares.NewStepUpMiddleware(stepUpService),
		AdminRoleMiddleware: middlewares.NewRoleMiddleware([]domain.UserRole{domain.RoleAdmin}),
	}, nil
}

func newEmailProvider(cfg config.EmailConfig) domain.EmailProvider {
	if cfg.ResendAPIKey == "" {
		return providers.NewLogEmailProvider()
	}
	return providers.NewResendEmailProvider(cfg.ResendAPIKey, cfg.From)
}
