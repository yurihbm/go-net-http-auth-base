package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime/debug"

	"go-net-http-auth-base/config"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

var extraMetricReaders []sdkmetric.Reader

type Telemetry struct {
	Enabled        bool
	TracerProvider trace.TracerProvider
	MeterProvider  metric.MeterProvider
	LoggerProvider log.LoggerProvider

	shutdownTraces  func(context.Context) error
	shutdownMetrics func(context.Context) error
	shutdownLogs    func(context.Context) error
}

func New(ctx context.Context, cfg config.TelemetryConfig, environment string) (*Telemetry, error) {
	if !cfg.Enabled {
		return &Telemetry{
			TracerProvider: tracenoop.NewTracerProvider(),
			MeterProvider:  metricnoop.NewMeterProvider(),
			LoggerProvider: lognoop.NewLoggerProvider(),
		}, nil
	}

	res, err := newResource(cfg.ServiceName, environment)
	if err != nil {
		return nil, err
	}

	traceExporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.Endpoint))
	if err != nil {
		return nil, err
	}
	metricExporter, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(cfg.Endpoint))
	if err != nil {
		return nil, err
	}
	logExporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(cfg.Endpoint))
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(newSampler(cfg.SampleRatio)),
		sdktrace.WithBatcher(traceExporter),
	)
	meterOptions := []sdkmetric.Option{
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
	}
	for _, reader := range extraMetricReaders {
		meterOptions = append(meterOptions, sdkmetric.WithReader(reader))
	}
	mp := sdkmetric.NewMeterProvider(meterOptions...)
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
	)

	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return nil, errors.Join(err, tp.Shutdown(ctx), mp.Shutdown(ctx), lp.Shutdown(ctx))
	}

	errorLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		errorLogger.Error("OpenTelemetry error", "error", err)
	}))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Telemetry{
		Enabled:         true,
		TracerProvider:  tp,
		MeterProvider:   mp,
		LoggerProvider:  lp,
		shutdownTraces:  tp.Shutdown,
		shutdownMetrics: mp.Shutdown,
		shutdownLogs:    lp.Shutdown,
	}, nil
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil {
		return nil
	}

	var errs []error
	for _, shutdown := range []func(context.Context) error{
		t.shutdownTraces,
		t.shutdownMetrics,
		t.shutdownLogs,
	} {
		if shutdown == nil {
			continue
		}
		if err := shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func newResource(serviceName, environment string) (*resource.Resource, error) {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}

	return resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
			semconv.DeploymentEnvironmentName(environment),
		),
	)
}

func newSampler(ratio float64) sdktrace.Sampler {
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}
