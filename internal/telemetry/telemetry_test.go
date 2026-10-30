package telemetry_test

import (
	"context"
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/telemetry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
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
		var _ propagation.TextMapPropagator = otel.GetTextMapPropagator()
	})

	t.Run("enabled - resource has service.name, service.version and deployment.environment.name", func(t *testing.T) {
		res, err := telemetry.NewResource("test-service", "staging")

		require.NoError(t, err)
		attrs := map[string]string{}
		for _, kv := range res.Attributes() {
			attrs[string(kv.Key)] = kv.Value.Emit()
		}
		assert.Equal(t, "test-service", attrs["service.name"])
		assert.NotEmpty(t, attrs["service.version"])
		assert.Equal(t, "staging", attrs["deployment.environment.name"])
	})

	t.Run("enabled - exposes go runtime metrics", func(t *testing.T) {
		restoreGlobals(t)
		reader := sdkmetric.NewManualReader()
		telemetry.SetExtraMetricReaders(reader)
		t.Cleanup(func() { telemetry.SetExtraMetricReaders() })

		_, err := telemetry.New(context.Background(), enabledConfig(), "test")
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

func TestNewSampler(t *testing.T) {
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rootParams := sdktrace.SamplingParameters{
		ParentContext: context.Background(),
		TraceID:       traceID,
		Name:          "op",
	}
	withParent := func(sampled bool) sdktrace.SamplingParameters {
		flags := trace.TraceFlags(0)
		if sampled {
			flags = trace.FlagsSampled
		}
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     trace.SpanID{1},
			TraceFlags: flags,
			Remote:     true,
		})
		return sdktrace.SamplingParameters{
			ParentContext: trace.ContextWithSpanContext(context.Background(), sc),
			TraceID:       traceID,
			Name:          "op",
		}
	}

	t.Run("ratio 0 never samples a root span", func(t *testing.T) {
		s := telemetry.NewSampler(0)
		assert.Equal(t, sdktrace.Drop, s.ShouldSample(rootParams).Decision)
	})

	t.Run("ratio 1 always samples a root span", func(t *testing.T) {
		s := telemetry.NewSampler(1)
		assert.Equal(t, sdktrace.RecordAndSample, s.ShouldSample(rootParams).Decision)
	})

	t.Run("respects a sampled parent", func(t *testing.T) {
		s := telemetry.NewSampler(0)
		assert.Equal(t, sdktrace.RecordAndSample, s.ShouldSample(withParent(true)).Decision)
	})

	t.Run("respects an unsampled parent", func(t *testing.T) {
		s := telemetry.NewSampler(1)
		assert.Equal(t, sdktrace.Drop, s.ShouldSample(withParent(false)).Decision)
	})
}
