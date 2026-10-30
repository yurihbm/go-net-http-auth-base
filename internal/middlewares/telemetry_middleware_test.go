package middlewares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type telemetryTestEnv struct {
	handler  http.Handler
	recorder *tracetest.SpanRecorder
	reader   *sdkmetric.ManualReader
}

func newTelemetryTestEnv() *telemetryTestEnv {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	telemetry := middlewares.NewTelemetryMiddleware(tp, mp, propagation.TraceContext{}, "api.test:8080")
	handler := middlewares.NewRequestContextDataMiddleware().Use(
		middlewares.NewRequestUUIDMiddleware().Use(
			telemetry.Use(
				middlewares.NewLoggerMiddleware().Use(mux),
			),
		),
	)

	return &telemetryTestEnv{handler: handler, recorder: recorder, reader: reader}
}

func (e *telemetryTestEnv) serve(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}

func (e *telemetryTestEnv) durationPoints(t *testing.T) []metricdata.HistogramDataPoint[float64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, e.reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "http.server.request.duration" {
				return m.Data.(metricdata.Histogram[float64]).DataPoints
			}
		}
	}
	return nil
}

func spanAttr(attrs []attribute.KeyValue, key attribute.Key) (attribute.Value, bool) {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

func TestTelemetryMiddleware_Use(t *testing.T) {
	t.Run("span named by route pattern with http.route and status code", func(t *testing.T) {
		env := newTelemetryTestEnv()

		env.serve(httptest.NewRequest(http.MethodGet, "/users/abc", nil))

		spans := env.recorder.Ended()
		require.Len(t, spans, 1)
		assert.Equal(t, "GET /users/{uuid}", spans[0].Name())
		route, ok := spanAttr(spans[0].Attributes(), "http.route")
		assert.True(t, ok)
		assert.Equal(t, "/users/{uuid}", route.AsString())
		status, ok := spanAttr(spans[0].Attributes(), "http.response.status_code")
		assert.True(t, ok)
		assert.Equal(t, int64(http.StatusOK), status.AsInt64())
		assert.Equal(t, codes.Unset, spans[0].Status().Code)
	})

	t.Run("duration metric with route, method, status and constant server.address and server.port", func(t *testing.T) {
		env := newTelemetryTestEnv()
		req := httptest.NewRequest(http.MethodGet, "/users/abc", nil)
		req.Host = "evil-123:54321"

		env.serve(req)

		points := env.durationPoints(t)
		require.Len(t, points, 1)
		attrs := points[0].Attributes
		route, _ := attrs.Value("http.route")
		assert.Equal(t, "/users/{uuid}", route.AsString())
		method, _ := attrs.Value("http.request.method")
		assert.Equal(t, http.MethodGet, method.AsString())
		status, _ := attrs.Value("http.response.status_code")
		assert.Equal(t, int64(http.StatusOK), status.AsInt64())
		server, _ := attrs.Value("server.address")
		assert.Equal(t, "api.test", server.AsString())
		port, _ := attrs.Value("server.port")
		assert.Equal(t, int64(8080), port.AsInt64())
		for _, kv := range attrs.ToSlice() {
			assert.NotContains(t, kv.Value.Emit(), "evil-123")
		}
	})

	t.Run("unmatched route - span named by method without http.route", func(t *testing.T) {
		env := newTelemetryTestEnv()

		env.serve(httptest.NewRequest(http.MethodGet, "/nope", nil))

		spans := env.recorder.Ended()
		require.Len(t, spans, 1)
		assert.Equal(t, http.MethodGet, spans[0].Name())
		_, ok := spanAttr(spans[0].Attributes(), "http.route")
		assert.False(t, ok)
		points := env.durationPoints(t)
		require.Len(t, points, 1)
		_, ok = points[0].Attributes.Value("http.route")
		assert.False(t, ok)
	})

	t.Run("health and ready - no spans and no metrics", func(t *testing.T) {
		env := newTelemetryTestEnv()

		w := env.serve(httptest.NewRequest(http.MethodGet, "/health", nil))
		assert.Equal(t, http.StatusOK, w.Code)
		w = env.serve(httptest.NewRequest(http.MethodGet, "/ready", nil))
		assert.Equal(t, http.StatusOK, w.Code)

		assert.Empty(t, env.recorder.Ended())
		assert.Empty(t, env.durationPoints(t))
	})

	t.Run("incoming traceparent becomes the parent", func(t *testing.T) {
		env := newTelemetryTestEnv()
		req := httptest.NewRequest(http.MethodGet, "/users/abc", nil)
		req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

		env.serve(req)

		spans := env.recorder.Ended()
		require.Len(t, spans, 1)
		assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", spans[0].SpanContext().TraceID().String())
		assert.Equal(t, "00f067aa0ba902b7", spans[0].Parent().SpanID().String())
		assert.True(t, spans[0].Parent().IsRemote())
	})

	t.Run("request uuid on span only, never on metrics", func(t *testing.T) {
		env := newTelemetryTestEnv()

		w := env.serve(httptest.NewRequest(http.MethodGet, "/users/abc", nil))

		requestUUID := w.Header().Get("X-Request-UUID")
		require.NotEmpty(t, requestUUID)
		spans := env.recorder.Ended()
		require.Len(t, spans, 1)
		value, ok := spanAttr(spans[0].Attributes(), "app.request.uuid")
		assert.True(t, ok)
		assert.Equal(t, requestUUID, value.AsString())
		points := env.durationPoints(t)
		require.Len(t, points, 1)
		_, ok = points[0].Attributes.Value("app.request.uuid")
		assert.False(t, ok)
	})

	t.Run("5xx marks span as error", func(t *testing.T) {
		env := newTelemetryTestEnv()

		env.serve(httptest.NewRequest(http.MethodGet, "/boom", nil))

		spans := env.recorder.Ended()
		require.Len(t, spans, 1)
		assert.Equal(t, codes.Error, spans[0].Status().Code)
	})
}
