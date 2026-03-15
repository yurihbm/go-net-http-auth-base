package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
)

// Replaces slog.Default with a JSON logger writing to buf.
// The returned function restores the original default logger.
func captureLogger(buf *bytes.Buffer) func() {
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	original := slog.Default()
	slog.SetDefault(logger)
	return func() { slog.SetDefault(original) }
}

func TestNewSlowQueryTracer(t *testing.T) {
	t.Run("uses default threshold when env var is unset", func(t *testing.T) {
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "")

		tracer := postgres.NewSlowQueryTracer()

		assert.Equal(t, 200*time.Millisecond, tracer.Threshold())
	})

	t.Run("reads threshold from env var", func(t *testing.T) {
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "500ms")

		tracer := postgres.NewSlowQueryTracer()

		assert.Equal(t, 500*time.Millisecond, tracer.Threshold())
	})

	t.Run("falls back to default on invalid env value", func(t *testing.T) {
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "not-a-duration")

		tracer := postgres.NewSlowQueryTracer()

		assert.Equal(t, 200*time.Millisecond, tracer.Threshold())
	})

	t.Run("accepts zero threshold", func(t *testing.T) {
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")

		tracer := postgres.NewSlowQueryTracer()

		assert.Equal(t, time.Duration(0), tracer.Threshold())
	})
}

func TestSlowQueryTracer_Threshold(t *testing.T) {
	t.Run("returns the configured threshold", func(t *testing.T) {
		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "1s")

		tracer := postgres.NewSlowQueryTracer()

		assert.Equal(t, time.Second, tracer.Threshold())
	})
}

func TestSlowQueryTracer_TraceQueryStart(t *testing.T) {
	t.Run("returns an enriched context with start time and SQL", func(t *testing.T) {
		tracer := postgres.NewSlowQueryTracer()
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
		tracer := postgres.NewSlowQueryTracer()
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

		tracer := postgres.NewSlowQueryTracer()
		tracer.TraceQueryEnd(context.Background(), nil, pgx.TraceQueryEndData{})

		assert.Empty(t, buf.String())
	})

	t.Run("does not log when elapsed time is below threshold", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "1h")
		tracer := postgres.NewSlowQueryTracer()

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

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")
		tracer := postgres.NewSlowQueryTracer()

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

	t.Run("includes request_uuid in log when present in context", func(t *testing.T) {
		var buf bytes.Buffer
		restore := captureLogger(&buf)
		defer restore()

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")
		tracer := postgres.NewSlowQueryTracer()

		ctx := context.WithValue(
			context.Background(),
			api.RequestContextDataKey,
			api.RequestContextData{RequestUUID: "test-req-uuid"},
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

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")
		tracer := postgres.NewSlowQueryTracer()

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

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")
		tracer := postgres.NewSlowQueryTracer()

		ctx := context.WithValue(
			context.Background(),
			api.RequestContextDataKey,
			api.RequestContextData{RequestUUID: ""},
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

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")
		tracer := postgres.NewSlowQueryTracer()

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

		t.Setenv("DB_SLOW_QUERY_THRESHOLD", "0s")
		tracer := postgres.NewSlowQueryTracer()

		ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
			SQL: "SELECT ok",
		})
		tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

		logOutput := buf.String()
		assert.NotContains(t, logOutput, `"error"`)
	})
}
