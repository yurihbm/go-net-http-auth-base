package factories

import (
	"context"
	"net"
	"net/http"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/telemetry"
)

func NewHandler(ctx context.Context, deps *Dependencies, cfg *config.Config, tel *telemetry.Telemetry) http.Handler {
	mux := http.NewServeMux()
	UsersFactory(deps, cfg).RegisterRoutes(mux)
	AuthFactory(deps, cfg).RegisterRoutes(mux)
	HealthFactory(deps).RegisterRoutes(mux)
	AuditFactory(deps).RegisterRoutes(mux)
	DocsFactory(deps).RegisterRoutes(mux)

	rateLimitMiddleware := RateLimitFactory(ctx, cfg.RateLimit)
	corsMiddleware := CORSFactory(cfg.CORS)
	loggerMiddleware := LoggerFactory()
	recoverMiddleware := RecoverFactory()
	telemetryMiddleware := TelemetryFactory(tel, net.JoinHostPort(cfg.Telemetry.ServiceName, cfg.Port))
	requestIDMiddleware := RequestUUIDFactory()
	requestContextDataMiddleware := RequestContextDataFactory()
	clientIPMiddleware := ClientIPFactory(cfg.TrustedProxies)
	return requestContextDataMiddleware.Use(
		clientIPMiddleware.Use(
			requestIDMiddleware.Use(
				telemetryMiddleware.Use(
					loggerMiddleware.Use(
						recoverMiddleware.Use(
							corsMiddleware.Use(
								rateLimitMiddleware.Use(
									mux,
								),
							),
						),
					),
				),
			),
		),
	)
}
