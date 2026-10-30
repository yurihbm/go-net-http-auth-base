package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"go-net-http-auth-base/internal/shared"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
)

// captureLogger replaces slog.Default with a JSON logger writing to buf.
// The returned function restores the original default logger.
func captureLogger(buf *bytes.Buffer) func() {
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	original := slog.Default()
	slog.SetDefault(logger)
	return func() { slog.SetDefault(original) }
}

func TestNewSlowQueryTracer(t *testing.T) {
	t.Run("uses the given threshold", func(t *testing.T) {
		tracer := postgres.NewSlowQueryTracer(500 * time.Millisecond)

		assert.Equal(t, 500*time.Millisecond, tracer.Threshold())
	})

	t.Run("accepts zero threshold", func(t *testing.T) {
		tracer := postgres.NewSlowQueryTracer(0)

		assert.Equal(t, time.Duration(0), tracer.Threshold())
	})
}

func TestSlowQueryTracer_TraceQueryStart(t *testing.T) {
	t.Run("returns an enriched context with start time and SQL", func(t *testing.T) {
		tracer := postgres.NewSlowQueryTracer(200 * time.Millisecond)
		ctx := context.Background()

		before := time.Now()
		enriched := tracer.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{
			SQL: "SELECT 1",
		})
		after := time.Now()

		startTime, ok := enriched.Value(postgres.QueryStartTimeKey).(time.Time)
		assert.True(t, ok, "start time should be stored in context")
		assert.False(t, startTime.Before(before), "start time should be >= before")
		assert.False(t, startTime.After(after), "start time should be <= after")

		sql, ok := enriched.Value(postgres.QuerySQLKey).(string)
		assert.True(t, ok, "sql should be stored in context")
		assert.Equal(t, "SELECT 1", sql)
	})

	t.Run("does not mutate the parent context", func(t *testing.T) {
		tracer := postgres.NewSlowQueryTracer(200 * time.Millisecond)
		parent := context.Background()

		tracer.TraceQueryStart(parent, nil, pgx.TraceQueryStartData{
			SQL: "SELECT 1",
		})

		assert.Nil(t, parent.Value(postgres.QueryStartTimeKey))
		assert.Nil(t, parent.Value(postgres.QuerySQLKey))
	})
}

func TestSlowQueryTracer_TraceQueryEnd(t *testing.T) {
	t.Run("does nothing when start time is missing from context", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(200 * time.Millisecond)
		tracer.TraceQueryEnd(context.Background(), nil, pgx.TraceQueryEndData{})

		assert.Empty(t, buf.String())
	})

	t.Run("does not log when elapsed time is below threshold", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(time.Hour)

		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
			SQL: "SELECT fast",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		assert.Empty(t, buf.String())
	})

	t.Run("logs a warning when elapsed time exceeds threshold", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(0)

		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
			SQL: "SELECT slow",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		logOutput := buf.String()
		assert.Contains(t, logOutput, `"level":"WARN"`)
		assert.Contains(t, logOutput, "slow query detected")
		assert.Contains(t, logOutput, `"duration_ms"`)
		assert.Contains(t, logOutput, `"sql":"SELECT slow"`)
	})

	t.Run("carries trace context when ctx has a span", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()
		slog.SetDefault(slog.New(&spanAttrHandler{inner: slog.Default().Handler()}))

		tracer := postgres.NewSlowQueryTracer(0)
		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "SELECT slow"})
		ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{1},
			SpanID:  trace.SpanID{1},
		}))
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		assert.Contains(t, buf.String(), `"has_span":true`)
	})

	t.Run("includes request_uuid in log when present in context", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(0)

		ctx := context.WithValue(
			context.Background(),
			shared.RequestContextDataKey,
			&shared.RequestContextData{RequestUUID: "test-req-uuid"},
		)
		ctx = tracer.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{
			SQL: "SELECT 1",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		logOutput := buf.String()
		assert.Contains(t, logOutput, `"request_uuid":"test-req-uuid"`)
	})

	t.Run("omits request_uuid when RequestContextData is absent", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(0)

		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
			SQL: "SELECT 1",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		logOutput := buf.String()
		assert.NotContains(t, logOutput, "request_uuid")
	})

	t.Run("omits request_uuid when RequestUUID field is empty", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(0)

		ctx := context.WithValue(
			context.Background(),
			shared.RequestContextDataKey,
			shared.RequestContextData{RequestUUID: ""},
		)
		ctx = tracer.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{
			SQL: "SELECT 1",
		})

		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		logOutput := buf.String()
		assert.NotContains(t, logOutput, "request_uuid")
	})

	t.Run("includes error in log when TraceQueryEndData carries an error", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(0)

		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
			SQL: "SELECT bad",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{
			Err: errors.New("db error"),
		})

		logOutput := buf.String()
		assert.Contains(t, logOutput, `"error":"db error"`)
	})

	t.Run("omits error field when TraceQueryEndData has no error", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		tracer := postgres.NewSlowQueryTracer(0)

		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
			SQL: "SELECT ok",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		logOutput := buf.String()
		assert.NotContains(t, logOutput, `"error"`)
	})
}

type spanAttrHandler struct{ inner slog.Handler }

func (h *spanAttrHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *spanAttrHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.Bool("has_span", trace.SpanContextFromContext(ctx).IsValid()))
	return h.inner.Handle(ctx, r)
}

func (h *spanAttrHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &spanAttrHandler{inner: h.inner.WithAttrs(a)}
}

func (h *spanAttrHandler) WithGroup(n string) slog.Handler {
	return &spanAttrHandler{inner: h.inner.WithGroup(n)}
}
