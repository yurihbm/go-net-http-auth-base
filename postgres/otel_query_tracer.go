package postgres

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace"
)

type otelQueryContextKey struct{}

type otelQueryState struct {
	span      trace.Span
	startedAt time.Time
	name      string
	operation string
}

var (
	sqlcNamePattern   = regexp.MustCompile(`^\s*--\s*name:\s*(\w+)`)
	sqlKeywordPattern = regexp.MustCompile(`(?m)^\s*([A-Za-z]+)`)
	durationBuckets   = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}
)

type OTelQueryTracer struct {
	tracer   trace.Tracer
	duration metric.Float64Histogram
}

var _ pgx.QueryTracer = (*OTelQueryTracer)(nil)

func NewOTelQueryTracer(tp trace.TracerProvider, mp metric.MeterProvider) (*OTelQueryTracer, error) {
	duration, err := mp.Meter("go-net-http-auth-base/postgres").Float64Histogram(
		"db.client.operation.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of database client operations."),
		metric.WithExplicitBucketBoundaries(durationBuckets...),
	)
	if err != nil {
		return nil, err
	}

	return &OTelQueryTracer{
		tracer:   tp.Tracer("go-net-http-auth-base/postgres"),
		duration: duration,
	}, nil
}

func (t *OTelQueryTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	operation := sqlOperation(data.SQL)
	name := sqlcQueryName(data.SQL)
	if name == "" {
		name = operation
	}
	if name == "" {
		name = "query"
	}

	attrs := []attribute.KeyValue{
		semconv.DBSystemNamePostgreSQL,
		semconv.DBQuerySummary(name),
		semconv.DBQueryText(strings.Join(strings.Fields(data.SQL), " ")),
	}
	if operation != "" {
		attrs = append(attrs, semconv.DBOperationName(operation))
	}
	if conn != nil {
		attrs = append(attrs, semconv.DBNamespace(conn.Config().Database))
	}

	ctx, span := t.tracer.Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	return context.WithValue(ctx, otelQueryContextKey{}, &otelQueryState{
		span:      span,
		startedAt: time.Now(),
		name:      name,
		operation: operation,
	})
}

func (t *OTelQueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	state, ok := ctx.Value(otelQueryContextKey{}).(*otelQueryState)
	if !ok {
		return
	}

	attrs := []attribute.KeyValue{
		semconv.DBSystemNamePostgreSQL,
		semconv.DBQuerySummary(state.name),
	}
	if state.operation != "" {
		attrs = append(attrs, semconv.DBOperationName(state.operation))
	}

	if data.Err != nil && !errors.Is(data.Err, pgx.ErrNoRows) {
		errType := semconv.ErrorType(data.Err)
		state.span.RecordError(data.Err)
		state.span.SetStatus(codes.Error, data.Err.Error())
		state.span.SetAttributes(errType)
		attrs = append(attrs, errType)
	}
	state.span.End()

	t.duration.Record(ctx, time.Since(state.startedAt).Seconds(), metric.WithAttributes(attrs...))
}

func sqlcQueryName(sql string) string {
	match := sqlcNamePattern.FindStringSubmatch(sql)
	if match == nil {
		return ""
	}
	return match[1]
}

func sqlOperation(sql string) string {
	for _, line := range strings.Split(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		if match := sqlKeywordPattern.FindStringSubmatch(line); match != nil {
			return strings.ToUpper(match[1])
		}
	}
	return ""
}
