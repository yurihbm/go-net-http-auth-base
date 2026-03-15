package postgres

import (
	"context"
	"log/slog"
	"time"

	"go-net-http-auth-base/internal/env"
	"go-net-http-auth-base/internal/shared"

	"github.com/jackc/pgx/v5"
)

const defaultSlowQueryThreshold = 200 * time.Millisecond

type QueryTracerContextKey string

const (
	QueryStartTimeKey QueryTracerContextKey = "slow_query_start_time"
	QuerySQLKey       QueryTracerContextKey = "slow_query_sql"
)

type SlowQueryTracer struct {
	threshold time.Duration
}

var _ pgx.QueryTracer = (*SlowQueryTracer)(nil)

// NewSlowQueryTracer returns a new SlowQueryTracer with the threshold
// configured from the DB_SLOW_QUERY_THRESHOLD environment variable.
func NewSlowQueryTracer() *SlowQueryTracer {
	return &SlowQueryTracer{
		threshold: env.GetEnvAsDuration("DB_SLOW_QUERY_THRESHOLD", defaultSlowQueryThreshold),
	}
}

// Threshold returns the configured slow-query threshold.
func (t *SlowQueryTracer) Threshold() time.Duration {
	return t.threshold
}

// TraceQueryStart records the query start time and SQL into the context.
func (t *SlowQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	ctx = context.WithValue(ctx, QueryStartTimeKey, time.Now())
	ctx = context.WithValue(ctx, QuerySQLKey, data.SQL)
	return ctx
}

// TraceQueryEnd measures the elapsed time and logs a warning if it exceeds the
// threshold. When a RequestUUID is present in the context (set by the
// RequestUUIDMiddleware) it is included in the log entry so the slow query can
// be correlated with the originating request.
func (t *SlowQueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	startTime, ok := ctx.Value(QueryStartTimeKey).(time.Time)
	if !ok {
		return
	}

	elapsed := time.Since(startTime)
	if elapsed < t.threshold {
		return
	}

	sql, _ := ctx.Value(QuerySQLKey).(string)

	args := []any{
		"duration_ms", elapsed.Milliseconds(),
		"sql", sql,
	}

	if reqData, ok := ctx.Value(shared.RequestContextDataKey).(shared.RequestContextData); ok && reqData.RequestUUID != "" {
		args = append(args, "request_uuid", reqData.RequestUUID)
	}

	if data.Err != nil {
		args = append(args, "error", data.Err)
	}

	slog.Warn("slow query detected", args...)
}
