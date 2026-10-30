package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
)

func RegisterPoolMetrics(pool *pgxpool.Pool, mp metric.MeterProvider) (metric.Registration, error) {
	meter := mp.Meter("go-net-http-auth-base/postgres")

	count, err := meter.Int64ObservableUpDownCounter(
		"db.client.connection.count",
		metric.WithUnit("{connection}"),
		metric.WithDescription("Number of connections currently in the pool, by state."),
	)
	if err != nil {
		return nil, err
	}
	maxConns, err := meter.Int64ObservableUpDownCounter(
		"db.client.connection.max",
		metric.WithUnit("{connection}"),
		metric.WithDescription("Maximum number of connections allowed in the pool."),
	)
	if err != nil {
		return nil, err
	}
	emptyAcquire, err := meter.Int64ObservableCounter(
		"db.client.connection.empty_acquire",
		metric.WithUnit("{acquire}"),
		metric.WithDescription("Acquires that had to wait because the pool had no idle connection."),
	)
	if err != nil {
		return nil, err
	}

	return meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			stat := pool.Stat()
			o.ObserveInt64(count, int64(stat.IdleConns()), metric.WithAttributes(semconv.DBClientConnectionStateIdle))
			o.ObserveInt64(count, int64(stat.AcquiredConns()), metric.WithAttributes(semconv.DBClientConnectionStateUsed))
			o.ObserveInt64(maxConns, int64(stat.MaxConns()))
			o.ObserveInt64(emptyAcquire, stat.EmptyAcquireCount())
			return nil
		},
		count, maxConns, emptyAcquire,
	)
}
