package factories

import (
	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/providers"
	"go-net-http-auth-base/internal/repositories"
	"go-net-http-auth-base/internal/services"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Dependencies struct {
	Pool *pgxpool.Pool

	UsersService        domain.UsersService
	EmailChangeService  domain.EmailChangeService
	AuthService         domain.AuthService
	AuditService        domain.AuditService
	StepUpService       domain.StepUpService
	FeatureFlagsService domain.FeatureFlagsService

	PendingSignupService domain.PendingSignupService
	PasswordService      domain.PasswordService

	EmailProvider domain.EmailProvider

	AuthMiddleware         middlewares.HandlerMiddleware
	OptionalAuthMiddleware middlewares.HandlerMiddleware
	StepUpMiddleware       middlewares.HandlerMiddleware
	AdminRoleMiddleware    middlewares.HandlerMiddleware
}

type Option func(*options)

type options struct {
	emailProvider domain.EmailProvider
}

func WithEmailProvider(provider domain.EmailProvider) Option {
	return func(o *options) { o.emailProvider = provider }
}

func NewDependencies(pool *pgxpool.Pool, cfg *config.Config, opts ...Option) (*Dependencies, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	db := repositories.NewTxAwareDB(pool)

	tokenService := services.NewTokenService(cfg.JWTSecret, time.Now)
	emailProvider := o.emailProvider
	if emailProvider == nil {
		emailProvider = newEmailProvider(cfg.Env, cfg.Email)
	}
	emailVerificationService := services.NewEmailVerificationService(tokenService, emailProvider, cfg.Email.ChangeRevertURL, cfg.Email.OAuthLinkRevertURL)

	usersRepository := repositories.NewUsersPostgresRepository(db)
	authRepository := repositories.NewAuthPostgresRepository(db)
	sessionsRepository := repositories.NewSessionsPostgresRepository(db)
	emailSendLimits := repositories.NewEmailSendLimitsPostgresRepository(db)
	sessionChallenges := repositories.NewSessionChallengesPostgresRepository(db)
	transactor := repositories.NewPostgresTransactor(pool)
	usersService := services.NewUserService(usersRepository, transactor, time.Now)
	emailChangeService := services.NewEmailChangeService(
		usersRepository,
		emailVerificationService,
		sessionsRepository,
		authRepository,
		sessionChallenges,
		emailSendLimits,
		transactor,
		[]byte(cfg.JWTSecret),
		time.Now,
	)
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
	pendingSignupService := services.NewPendingSignupService(
		repositories.NewPendingSignupsPostgresRepository(db),
		emailSendLimits,
		usersRepository,
		transactor,
		emailVerificationService,
		[]byte(cfg.JWTSecret),
		time.Now,
	)
	passwordService := services.NewPasswordService(
		repositories.NewPasswordResetsPostgresRepository(db),
		usersRepository,
		sessionsRepository,
		emailSendLimits,
		transactor,
		emailVerificationService,
		[]byte(cfg.JWTSecret),
		time.Now,
	)
	authService := services.NewAuthService(
		usersService,
		pendingSignupService,
		authRepository,
		sessionsRepository,
		oauthProviderRegistry,
		transactor,
		tokenService,
		emailVerificationService,
		cfg.SessionMaxAge,
		cfg.MaxSessionsPerUser,
		time.Now,
	)

	stepUpService := services.NewStepUpService(
		sessionChallenges,
		sessionsRepository,
		usersRepository,
		transactor,
		emailVerificationService,
		[]byte(cfg.JWTSecret),
		time.Now,
	)

	auditRepository := repositories.NewAuditPostgresRepository(db)
	auditService := services.NewAuditService(auditRepository)
	featureFlagsService := services.NewFeatureFlagsService(repositories.NewFeatureFlagsPostgresRepository(db))

	return &Dependencies{
		Pool:                   pool,
		UsersService:           usersService,
		EmailChangeService:     emailChangeService,
		AuthService:            authService,
		AuditService:           auditService,
		StepUpService:          stepUpService,
		FeatureFlagsService:    featureFlagsService,
		PendingSignupService:   pendingSignupService,
		PasswordService:        passwordService,
		EmailProvider:          emailProvider,
		AuthMiddleware:         middlewares.NewAuthMiddleware(authService),
		OptionalAuthMiddleware: middlewares.NewOptionalAuthMiddleware(authService),
		StepUpMiddleware:       middlewares.NewStepUpMiddleware(stepUpService),
		AdminRoleMiddleware:    middlewares.NewRoleMiddleware([]domain.UserRole{domain.RoleAdmin}),
	}, nil
}

func newEmailProvider(env string, cfg config.EmailConfig) domain.EmailProvider {
	if cfg.ResendAPIKey == "" {
		return providers.NewLogEmailProvider(env != "production")
	}
	return providers.NewResendEmailProvider(cfg.ResendAPIKey, cfg.From)
}
