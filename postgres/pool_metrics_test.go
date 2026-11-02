package postgres_test

import (
	"context"
	"testing"

	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func newUnconnectedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db?pool_max_conns=7&pool_min_conns=0")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func collectPoolMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	metrics := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metrics[m.Name] = m
		}
	}
	return metrics
}

func sumByState(t *testing.T, m metricdata.Metrics) map[string]int64 {
	t.Helper()
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	byState := map[string]int64{}
	for _, dp := range sum.DataPoints {
		state, _ := dp.Attributes.Value("db.client.connection.state")
		byState[state.AsString()] = dp.Value
	}
	return byState
}

func TestRegisterPoolMetrics(t *testing.T) {
	t.Run("reports max connections", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		reg, err := postgres.RegisterPoolMetrics(newUnconnectedPool(t), mp)
		require.NoError(t, err)
		t.Cleanup(func() { _ = reg.Unregister() })

		metrics := collectPoolMetrics(t, reader)

		sum, ok := metrics["db.client.connection.max"].Data.(metricdata.Sum[int64])
		require.True(t, ok)
		require.Len(t, sum.DataPoints, 1)
		assert.Equal(t, int64(7), sum.DataPoints[0].Value)
	})

	t.Run("reports idle and used as separate states", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		reg, err := postgres.RegisterPoolMetrics(newUnconnectedPool(t), mp)
		require.NoError(t, err)
		t.Cleanup(func() { _ = reg.Unregister() })

		metrics := collectPoolMetrics(t, reader)

		assert.Equal(t, map[string]int64{"idle": 0, "used": 0}, sumByState(t, metrics["db.client.connection.count"]))
	})

	t.Run("reports empty acquire count", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		reg, err := postgres.RegisterPoolMetrics(newUnconnectedPool(t), mp)
		require.NoError(t, err)
		t.Cleanup(func() { _ = reg.Unregister() })

		metrics := collectPoolMetrics(t, reader)

		sum, ok := metrics["db.client.connection.empty_acquire"].Data.(metricdata.Sum[int64])
		require.True(t, ok)
		assert.True(t, sum.IsMonotonic)
		require.Len(t, sum.DataPoints, 1)
		assert.Equal(t, int64(0), sum.DataPoints[0].Value)
	})

	t.Run("unregister stops reporting", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		reg, err := postgres.RegisterPoolMetrics(newUnconnectedPool(t), mp)
		require.NoError(t, err)
		require.Contains(t, collectPoolMetrics(t, reader), "db.client.connection.max")

		require.NoError(t, reg.Unregister())

		assert.NotContains(t, collectPoolMetrics(t, reader), "db.client.connection.max")
	})
}
