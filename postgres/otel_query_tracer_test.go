package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
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
		m[string(kv.Key)] = kv.Value.String()
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

type attributeCollectingTracerProvider struct {
	trace.TracerProvider
	recording bool
	attrs     []attribute.KeyValue
}

type attributeCollectingTracer struct {
	trace.Tracer
	provider *attributeCollectingTracerProvider
}

type attributeCollectingSpan struct {
	trace.Span
	provider *attributeCollectingTracerProvider
}

func (p *attributeCollectingTracerProvider) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	return &attributeCollectingTracer{Tracer: p.TracerProvider.Tracer(name, opts...), provider: p}
}

func (t *attributeCollectingTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	ctx, span := t.Tracer.Start(ctx, name, opts...)
	return ctx, &attributeCollectingSpan{Span: span, provider: t.provider}
}

func (s *attributeCollectingSpan) IsRecording() bool {
	return s.provider.recording
}

func (s *attributeCollectingSpan) SetAttributes(kv ...attribute.KeyValue) {
	s.provider.attrs = append(s.provider.attrs, kv...)
	s.Span.SetAttributes(kv...)
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

	t.Run("same sql twice yields identical spans", func(t *testing.T) {
		tracer, recorder, _, _ := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), sqlcQuery, nil, nil)
		runQuery(tracer, context.Background(), sqlcQuery, nil, nil)

		spans := recorder.Ended()
		require.Len(t, spans, 2)
		assert.Equal(t, spans[0].Name(), spans[1].Name())
		assert.Equal(t, attrMap(spans[0].Attributes()), attrMap(spans[1].Attributes()))
	})

	t.Run("dynamic sql is traced per call", func(t *testing.T) {
		tracer, recorder, _, _ := newTestOTelTracer(t)

		runQuery(tracer, context.Background(), "CREATE TABLE audit_logs_2026_01 (id int)", nil, nil)
		runQuery(tracer, context.Background(), "CREATE TABLE audit_logs_2026_02 (id int)", nil, nil)

		spans := recorder.Ended()
		require.Len(t, spans, 2)
		assert.Equal(t, "CREATE", spans[0].Name())
		assert.Contains(t, attrMap(spans[0].Attributes())["db.query.text"], "audit_logs_2026_01")
		assert.Contains(t, attrMap(spans[1].Attributes())["db.query.text"], "audit_logs_2026_02")
	})

	t.Run("sets db.query.text only when span is recording", func(t *testing.T) {
		for _, recording := range []bool{true, false} {
			recorder := tracetest.NewSpanRecorder()
			provider := &attributeCollectingTracerProvider{
				TracerProvider: sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)),
				recording:      recording,
			}
			tracer, err := postgres.NewOTelQueryTracer(provider, sdkmetric.NewMeterProvider())
			require.NoError(t, err)

			runQuery(tracer, context.Background(), sqlcQuery, nil, nil)

			var texts []string
			for _, kv := range provider.attrs {
				if kv.Key == "db.query.text" {
					texts = append(texts, kv.Value.String())
				}
			}
			for _, s := range recorder.Ended() {
				if text, ok := attrMap(s.Attributes())["db.query.text"]; ok && !recording {
					texts = append(texts, text)
				}
			}
			if recording {
				assert.Equal(t, []string{"-- name: GetUserByEmail :one SELECT uuid, email FROM users WHERE email = $1"}, texts)
			} else {
				assert.Empty(t, texts)
			}
		}
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
				assert.NotContains(t, kv.Value.String(), secret)
			}
			for _, e := range s.Events() {
				for _, kv := range e.Attributes {
					assert.NotContains(t, kv.Value.String(), secret)
				}
			}
		}
		for _, dp := range collectDuration(t, reader).DataPoints {
			for _, kv := range dp.Attributes.ToSlice() {
				assert.NotContains(t, kv.Value.String(), secret)
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

	t.Run("error.type", func(t *testing.T) {
		tests := []struct {
			name           string
			err            error
			wantType       string
			wantStatusCode bool
		}{
			{"pg error uses SQLSTATE", &pgconn.PgError{Code: "23505"}, "23505", true},
			{"wrapped pg error uses SQLSTATE", fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "40001"}), "40001", true},
			{"context canceled", fmt.Errorf("wrapped: %w", context.Canceled), "canceled", false},
			{"other error uses type name", errors.New("boom"), "*errors.errorString", false},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				tracer, recorder, _, reader := newTestOTelTracer(t)

				runQuery(tracer, context.Background(), sqlcQuery, nil, tc.err)

				span := recorder.Ended()[0]
				spanAttrs := attrMap(span.Attributes())
				assert.Equal(t, codes.Error, span.Status().Code)
				assert.NotEmpty(t, span.Events())
				assert.Equal(t, tc.wantType, spanAttrs["error.type"])
				if tc.wantStatusCode {
					assert.Equal(t, tc.wantType, spanAttrs["db.response.status_code"])
				} else {
					assert.NotContains(t, spanAttrs, "db.response.status_code")
				}
				dps := collectDuration(t, reader).DataPoints
				require.Len(t, dps, 1)
				assert.Equal(t, tc.wantType, attrMap(dps[0].Attributes.ToSlice())["error.type"])
				assert.NotContains(t, attrMap(dps[0].Attributes.ToSlice()), "db.response.status_code")
			})
		}
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

func BenchmarkOTelQueryTracer_TraceQuery(b *testing.B) {
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	variants := map[string]sdktrace.Sampler{
		"sampled":   sdktrace.AlwaysSample(),
		"unsampled": sdktrace.NeverSample(),
	}

	for name, sampler := range variants {
		b.Run(name, func(b *testing.B) {
			tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sampler))
			tracer, err := postgres.NewOTelQueryTracer(tp, mp)
			require.NoError(b, err)
			ctx := context.Background()

			b.ReportAllocs()
			for b.Loop() {
				runQuery(tracer, ctx, sqlcQuery, nil, nil)
			}
		})
	}
}
