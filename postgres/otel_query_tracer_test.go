package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const sqlcQuery = "-- name: GetUserByEmail :one\nSELECT uuid,\n    email\nFROM users\nWHERE email = $1"

func newTestOTelTracer(t *testing.T) (*postgres.OTelQueryTracer, *tracetest.SpanRecorder, *sdktrace.TracerProvider, *sdkmetric.ManualReader) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	tracer, err := postgres.NewOTelQueryTracer(tp, mp)
	require.NoError(t, err)
	return tracer, recorder, tp, reader
}

func attrMap(kvs []attribute.KeyValue) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.Emit()
	}
	return m
}

func collectDuration(t *testing.T, reader *sdkmetric.ManualReader) metricdata.Histogram[float64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "db.client.operation.duration" {
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				assert.Equal(t, "s", m.Unit)
				return hist
			}
		}
	}
	t.Fatal("db.client.operation.duration not recorded")
	return metricdata.Histogram[float64]{}
}

func runQuery(tracer *postgres.OTelQueryTracer, ctx context.Context, sql string, args []any, err error) {
	ctx = tracer.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: sql, Args: args})
	tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: err})
}

func TestOTelQueryTracer_TraceQueryStart(t *testing.T) {
	t.Run("names span from sqlc header", func(t *testing.T) {
		tracer, recorder, _, _ := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), sqlcQuery, nil, nil)

		spans := recorder.Ended()
		require.Len(t, spans, 1)
		assert.Equal(t, "GetUserByEmail", spans[0].Name())
		attrs := attrMap(spans[0].Attributes())
		assert.Equal(t, "postgresql", attrs["db.system.name"])
		assert.Equal(t, "GetUserByEmail", attrs["db.query.summary"])
		assert.Equal(t, "SELECT", attrs["db.operation.name"])
		assert.Contains(t, attrs["db.query.text"], "SELECT uuid, email FROM users WHERE email = $1")
	})

	t.Run("falls back to first keyword", func(t *testing.T) {
		tracer, recorder, _, _ := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), "  insert into users values ($1)", nil, nil)

		require.Len(t, recorder.Ended(), 1)
		assert.Equal(t, "INSERT", recorder.Ended()[0].Name())
	})

	t.Run("falls back to query when sql is empty", func(t *testing.T) {
		tracer, recorder, _, _ := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), "", nil, nil)

		require.Len(t, recorder.Ended(), 1)
		assert.Equal(t, "query", recorder.Ended()[0].Name())
	})

	t.Run("nests under parent span", func(t *testing.T) {
		tracer, recorder, tp, _ := newTestOTelTracer(t)
		ctx, parent := tp.Tracer("test").Start(context.Background(), "parent")

		runQuery(tracer, ctx, sqlcQuery, nil, nil)
		parent.End()

		var child sdktrace.ReadOnlySpan
		for _, s := range recorder.Ended() {
			if s.Name() == "GetUserByEmail" {
				child = s
			}
		}
		require.NotNil(t, child)
		assert.Equal(t, parent.SpanContext().SpanID(), child.Parent().SpanID())
		assert.Equal(t, "client", child.SpanKind().String())
	})
}

func TestOTelQueryTracer_TraceQueryEnd(t *testing.T) {
	t.Run("never records query args", func(t *testing.T) {
		tracer, recorder, _, reader := newTestOTelTracer(t)
		secret := "a@b.com"

		runQuery(tracer, context.Background(), sqlcQuery, []any{secret}, errors.New("boom"))

		for _, s := range recorder.Ended() {
			for _, kv := range s.Attributes() {
				assert.NotContains(t, kv.Value.Emit(), secret)
			}
			for _, e := range s.Events() {
				for _, kv := range e.Attributes {
					assert.NotContains(t, kv.Value.Emit(), secret)
				}
			}
		}
		for _, dp := range collectDuration(t, reader).DataPoints {
			for _, kv := range dp.Attributes.ToSlice() {
				assert.NotContains(t, kv.Value.Emit(), secret)
			}
		}
	})

	t.Run("error sets status and error.type", func(t *testing.T) {
		tracer, recorder, _, _ := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), sqlcQuery, nil, errors.New("boom"))

		span := recorder.Ended()[0]
		assert.Equal(t, codes.Error, span.Status().Code)
		assert.NotEmpty(t, attrMap(span.Attributes())["error.type"])
		assert.NotEmpty(t, span.Events())
	})

	t.Run("ErrNoRows is not an error", func(t *testing.T) {
		tracer, recorder, _, reader := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), sqlcQuery, nil, fmt.Errorf("wrapped: %w", pgx.ErrNoRows))

		span := recorder.Ended()[0]
		assert.Equal(t, codes.Unset, span.Status().Code)
		assert.NotContains(t, attrMap(span.Attributes()), "error.type")
		for _, dp := range collectDuration(t, reader).DataPoints {
			assert.NotContains(t, attrMap(dp.Attributes.ToSlice()), "error.type")
		}
	})

	t.Run("records duration with low cardinality attributes", func(t *testing.T) {
		tracer, _, _, reader := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), sqlcQuery, []any{"a@b.com"}, errors.New("boom"))

		hist := collectDuration(t, reader)
		require.Len(t, hist.DataPoints, 1)
		dp := hist.DataPoints[0]
		assert.Equal(t, uint64(1), dp.Count)
		assert.Equal(t, []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}, dp.Bounds)
		attrs := attrMap(dp.Attributes.ToSlice())
		assert.Len(t, attrs, 4)
		assert.Equal(t, "postgresql", attrs["db.system.name"])
		assert.Equal(t, "GetUserByEmail", attrs["db.query.summary"])
		assert.Equal(t, "SELECT", attrs["db.operation.name"])
		assert.NotEmpty(t, attrs["error.type"])
	})

	t.Run("ends cleanly when composed with slow query tracer", func(t *testing.T) {
		tracer, recorder, _, reader := newTestOTelTracer(t)
		slow := postgres.NewSlowQueryTracer(time.Hour)
		data := pgx.TraceQueryStartData{SQL: sqlcQuery}

		ctx := slow.TraceQueryStart(context.Background(), nil, data)
		ctx = tracer.TraceQueryStart(ctx, nil, data)
		assert.NotNil(t, ctx.Value(postgres.QueryStartTimeKey))
		assert.Equal(t, sqlcQuery, ctx.Value(postgres.QuerySQLKey))
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
		slow.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		assert.Len(t, recorder.Ended(), 1)
		assert.Len(t, collectDuration(t, reader).DataPoints, 1)
	})
}
