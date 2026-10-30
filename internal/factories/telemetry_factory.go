package factories

import (
	"net/http"

	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/telemetry"

	"go.opentelemetry.io/otel"
)

type passThroughMiddleware struct{}

func (passThroughMiddleware) Use(next http.Handler) http.Handler {
	return next
}

func TelemetryFactory(tel *telemetry.Telemetry, serverName string) middlewares.GlobalMiddleware {
	if !tel.Enabled {
		return passThroughMiddleware{}
	}
	return middlewares.NewTelemetryMiddleware(
		tel.TracerProvider,
		tel.MeterProvider,
		otel.GetTextMapPropagator(),
		serverName,
	)
}
