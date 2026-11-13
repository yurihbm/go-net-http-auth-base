package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/telemetry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	otellog "go.opentelemetry.io/otel/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func restoreGlobals(t *testing.T) {
	t.Helper()
	tp := otel.GetTracerProvider()
	mp := otel.GetMeterProvider()
	prop := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(tp)
		otel.SetMeterProvider(mp)
		otel.SetTextMapPropagator(prop)
	})
}

func enabledConfig() config.TelemetryConfig {
	return config.TelemetryConfig{
		Enabled:     true,
		ServiceName: "test-service",
		Endpoint:    "http://127.0.0.1:1",
		SampleRatio: 1,
	}
}

func remoteParent(flags trace.TraceFlags) context.Context {
	return trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1},
		TraceFlags: flags,
		Remote:     true,
	}))
}

func TestNew(t *testing.T) {
	t.Run("disabled - returns noop providers and Shutdown is a no-op", func(t *testing.T) {
		restoreGlobals(t)
		tpBefore := otel.GetTracerProvider()
		mpBefore := otel.GetMeterProvider()

		tel, err := telemetry.New(context.Background(), config.TelemetryConfig{}, "test")

		require.NoError(t, err)
		assert.False(t, tel.Enabled)
		assert.IsType(t, noop.TracerProvider{}, tel.TracerProvider)
		assert.NotNil(t, tel.MeterProvider)
		assert.NotNil(t, tel.LoggerProvider)
		assert.Equal(t, tpBefore, otel.GetTracerProvider())
		assert.Equal(t, mpBefore, otel.GetMeterProvider())
		assert.NoError(t, tel.Shutdown(context.Background()))
	})

	t.Run("enabled - returns SDK providers and sets the global tracer provider", func(t *testing.T) {
		restoreGlobals(t)

		tel, err := telemetry.New(context.Background(), enabledConfig(), "test")

		require.NoError(t, err)
		assert.True(t, tel.Enabled)
		assert.IsType(t, &sdktrace.TracerProvider{}, tel.TracerProvider)
		assert.IsType(t, &sdkmetric.MeterProvider{}, tel.MeterProvider)
		assert.Same(t, tel.TracerProvider, otel.GetTracerProvider())
		assert.Same(t, tel.MeterProvider, otel.GetMeterProvider())
		assert.Contains(t, otel.GetTextMapPropagator().Fields(), "traceparent")
		assert.Contains(t, otel.GetTextMapPropagator().Fields(), "baggage")
	})

	t.Run("enabled - resource has service.name, service.version and deployment.environment.name", func(t *testing.T) {
		restoreGlobals(t)
		tel, err := telemetry.New(context.Background(), enabledConfig(), "staging")
		require.NoError(t, err)

		_, span := tel.TracerProvider.Tracer("test").Start(context.Background(), "op")
		defer span.End()

		readable, ok := span.(sdktrace.ReadOnlySpan)
		require.True(t, ok)
		attrs := map[string]string{}
		for _, kv := range readable.Resource().Attributes() {
			attrs[string(kv.Key)] = kv.Value.String()
		}
		assert.Equal(t, "test-service", attrs["service.name"])
		assert.NotEmpty(t, attrs["service.version"])
		assert.Equal(t, "staging", attrs["deployment.environment.name"])
	})

	t.Run("enabled - ratio 0 never samples a root span", func(t *testing.T) {
		restoreGlobals(t)
		cfg := enabledConfig()
		cfg.SampleRatio = 0
		tel, err := telemetry.New(context.Background(), cfg, "test")
		require.NoError(t, err)

		_, span := tel.TracerProvider.Tracer("test").Start(context.Background(), "op")
		defer span.End()

		assert.False(t, span.SpanContext().IsSampled())
	})

	t.Run("enabled - ratio 1 always samples a root span", func(t *testing.T) {
		restoreGlobals(t)
		tel, err := telemetry.New(context.Background(), enabledConfig(), "test")
		require.NoError(t, err)

		_, span := tel.TracerProvider.Tracer("test").Start(context.Background(), "op")
		defer span.End()

		assert.True(t, span.SpanContext().IsSampled())
	})

	t.Run("enabled - respects a sampled parent", func(t *testing.T) {
		restoreGlobals(t)
		cfg := enabledConfig()
		cfg.SampleRatio = 0
		tel, err := telemetry.New(context.Background(), cfg, "test")
		require.NoError(t, err)

		_, span := tel.TracerProvider.Tracer("test").Start(remoteParent(trace.FlagsSampled), "op")
		defer span.End()

		assert.True(t, span.SpanContext().IsSampled())
	})

	t.Run("enabled - respects an unsampled parent", func(t *testing.T) {
		restoreGlobals(t)
		tel, err := telemetry.New(context.Background(), enabledConfig(), "test")
		require.NoError(t, err)

		_, span := tel.TracerProvider.Tracer("test").Start(remoteParent(0), "op")
		defer span.End()

		assert.False(t, span.SpanContext().IsSampled())
	})

	t.Run("enabled - exposes go runtime metrics", func(t *testing.T) {
		restoreGlobals(t)
		reader := sdkmetric.NewManualReader()

		_, err := telemetry.New(context.Background(), enabledConfig(), "test", telemetry.WithMetricReader(reader))
		require.NoError(t, err)

		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		names := []string{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				names = append(names, m.Name)
			}
		}
		assert.Contains(t, names, "go.goroutine.count")
	})

	t.Run("enabled - exports each signal to its OTLP path under the endpoint", func(t *testing.T) {
		restoreGlobals(t)
		var mu sync.Mutex
		paths := map[string]bool{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths[r.URL.Path] = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)
		cfg := enabledConfig()
		cfg.Endpoint = server.URL

		tel, err := telemetry.New(context.Background(), cfg, "test")
		require.NoError(t, err)
		_, span := tel.TracerProvider.Tracer("test").Start(context.Background(), "op")
		span.End()
		var record otellog.Record
		record.SetBody(otellog.StringValue("hello"))
		tel.LoggerProvider.Logger("test").Emit(context.Background(), record)
		require.NoError(t, tel.Shutdown(context.Background()))

		mu.Lock()
		defer mu.Unlock()
		assert.True(t, paths["/v1/traces"], "paths: %v", paths)
		assert.True(t, paths["/v1/metrics"], "paths: %v", paths)
		assert.True(t, paths["/v1/logs"], "paths: %v", paths)
	})

	t.Run("error - Shutdown returns error when context is already canceled", func(t *testing.T) {
		restoreGlobals(t)
		tel, err := telemetry.New(context.Background(), enabledConfig(), "test")
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, span := tel.TracerProvider.Tracer("test").Start(context.Background(), "op")
		span.End()

		assert.Error(t, tel.Shutdown(ctx))
	})
}

func TestTelemetry_Shutdown(t *testing.T) {
	t.Run("nil receiver is a no-op", func(t *testing.T) {
		var tel *telemetry.Telemetry
		assert.NoError(t, tel.Shutdown(context.Background()))
	})
}
