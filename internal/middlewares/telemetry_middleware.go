package middlewares

import (
	"net/http"
	"strings"

	"go-net-http-auth-base/internal/shared"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace"
)

type TelemetryMiddleware struct {
	opts []otelhttp.Option
}

func NewTelemetryMiddleware(
	tp trace.TracerProvider,
	mp metric.MeterProvider,
	prop propagation.TextMapPropagator,
	serverName string,
) GlobalMiddleware {
	return &TelemetryMiddleware{
		opts: []otelhttp.Option{
			otelhttp.WithTracerProvider(tp),
			otelhttp.WithMeterProvider(mp),
			otelhttp.WithPropagators(prop),
			otelhttp.WithServerName(serverName),
			otelhttp.WithFilter(isTracedRequest),
		},
	}
}

func (m *TelemetryMiddleware) Use(next http.Handler) http.Handler {
	return otelhttp.NewHandler(routeHook(next), "http.server", m.opts...)
}

func isTracedRequest(r *http.Request) bool {
	return r.Method != http.MethodGet || (r.URL.Path != "/health" && r.URL.Path != "/ready")
}

func routeHook(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)

		span := trace.SpanFromContext(r.Context())
		if i := strings.Index(r.Pattern, "/"); i >= 0 {
			span.SetAttributes(semconv.HTTPRoute(r.Pattern[i:]))
		}
		if data, ok := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData); ok && data.RequestUUID != "" {
			span.SetAttributes(attribute.String("app.request.uuid", data.RequestUUID))
		}
	})
}
