package postgres

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	query     *parsedQuery
}

type parsedQuery struct {
	name       string
	text       string
	baseAttrs  []attribute.KeyValue
	metricAttr metric.MeasurementOption
}

var (
	sqlcNamePattern   = regexp.MustCompile(`^\s*--\s*name:\s*(\w+)`)
	sqlKeywordPattern = regexp.MustCompile(`(?m)^\s*([A-Za-z]+)`)
	durationBuckets   = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}
)

type OTelQueryTracer struct {
	tracer    trace.Tracer
	duration  metric.Float64Histogram
	parsed    sync.Map
	namespace []attribute.KeyValue
}

var _ pgx.QueryTracer = (*OTelQueryTracer)(nil)

func NewOTelQueryTracer(tp trace.TracerProvider, mp metric.MeterProvider, database string) (*OTelQueryTracer, error) {
	duration, err := mp.Meter("go-net-http-auth-base/postgres").Float64Histogram(
		"db.client.operation.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of database client operations."),
		metric.WithExplicitBucketBoundaries(durationBuckets...),
	)
	if err != nil {
		return nil, err
	}

	tracer := &OTelQueryTracer{
		tracer:   tp.Tracer("go-net-http-auth-base/postgres"),
		duration: duration,
	}
	if database != "" {
		tracer.namespace = []attribute.KeyValue{semconv.DBNamespace(database)}
	}

	return tracer, nil
}

func (t *OTelQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	query := t.parse(data.SQL)

	ctx, span := t.tracer.Start(ctx, query.name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(query.baseAttrs...),
		trace.WithAttributes(t.namespace...),
	)
	if span.IsRecording() {
		text := query.text
		if text == "" {
			text = normalizeSQL(data.SQL)
		}
		span.SetAttributes(semconv.DBQueryText(text))
	}

	return context.WithValue(ctx, otelQueryContextKey{}, &otelQueryState{
		span:      span,
		startedAt: time.Now(),
		query:     query,
	})
}

func (t *OTelQueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	state, ok := ctx.Value(otelQueryContextKey{}).(*otelQueryState)
	if !ok {
		return
	}

	measurement := state.query.metricAttr
	if data.Err != nil && !errors.Is(data.Err, pgx.ErrNoRows) {
		errType, sqlState := errorType(data.Err)
		state.span.RecordError(data.Err)
		state.span.SetStatus(codes.Error, data.Err.Error())
		state.span.SetAttributes(errType)
		if sqlState != "" {
			state.span.SetAttributes(semconv.DBResponseStatusCode(sqlState))
		}
		attrs := append(slices.Clone(state.query.baseAttrs), errType)
		measurement = metric.WithAttributeSet(attribute.NewSet(attrs...))
	}
	state.span.End()

	t.duration.Record(ctx, time.Since(state.startedAt).Seconds(), measurement)
}

func (t *OTelQueryTracer) parse(sql string) *parsedQuery {
	if !strings.HasPrefix(sql, "--") {
		return parseQuery(sql, "")
	}
	if cached, ok := t.parsed.Load(sql); ok {
		return cached.(*parsedQuery)
	}
	cached, _ := t.parsed.LoadOrStore(sql, parseQuery(sql, normalizeSQL(sql)))
	return cached.(*parsedQuery)
}

func parseQuery(sql, text string) *parsedQuery {
	operation := sqlOperation(sql)
	name := sqlcQueryName(sql)
	if name == "" {
		name = operation
	}
	if name == "" {
		name = "query"
	}

	attrs := []attribute.KeyValue{
		semconv.DBSystemNamePostgreSQL,
		semconv.DBQuerySummary(name),
	}
	if operation != "" {
		attrs = append(attrs, semconv.DBOperationName(operation))
	}

	return &parsedQuery{
		name:       name,
		text:       text,
		baseAttrs:  attrs,
		metricAttr: metric.WithAttributeSet(attribute.NewSet(attrs...)),
	}
}

func normalizeSQL(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}

func errorType(err error) (attribute.KeyValue, string) {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return semconv.ErrorTypeKey.String(pgErr.Code), pgErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return semconv.ErrorTypeKey.String("canceled"), ""
	}
	return semconv.ErrorType(err), ""
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
