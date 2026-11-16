package factories

import (
	"net"
	"net/http"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/telemetry"
)

func NewHandler(deps *Dependencies, cfg *config.Config, tel *telemetry.Telemetry) http.Handler {
	mux := http.NewServeMux()
	UsersFactory(deps).RegisterRoutes(mux)
	AuthFactory(deps, cfg).RegisterRoutes(mux)
	HealthFactory(deps).RegisterRoutes(mux)
	AuditFactory(deps).RegisterRoutes(mux)
	DocsFactory(deps).RegisterRoutes(mux)

	rateLimitMiddleware := RateLimitFactory(cfg.RateLimit)
	corsMiddleware := CORSFactory(cfg.CORS)
	loggerMiddleware := LoggerFactory()
	telemetryMiddleware := TelemetryFactory(tel, net.JoinHostPort(cfg.Telemetry.ServiceName, cfg.Port))
	requestIDMiddleware := RequestUUIDFactory()
	requestContextDataMiddleware := RequestContextDataFactory()
	return requestContextDataMiddleware.Use(
		requestIDMiddleware.Use(
			telemetryMiddleware.Use(
				loggerMiddleware.Use(
					corsMiddleware.Use(
						rateLimitMiddleware.Use(
							mux,
						),
					),
				),
			),
		),
	)
}
