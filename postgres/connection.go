package postgres

import (
	"context"
	"fmt"
	"log/slog"

	"go-net-http-auth-base/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewConnectionPool creates a pgxpool.Pool using the given database config.
// The caller is responsible for closing the pool. The provided context
// controls the initial connection and ping timeout. All structured log
// output goes to slog.Default(), which is configured at application startup
// via logger.Setup().
func NewConnectionPool(ctx context.Context, dbCfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	if dbCfg.URL == "" {
		return nil, fmt.Errorf("DATABASE_URL not set in environment")
	}

	cfg, err := pgxpool.ParseConfig(dbCfg.URL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DATABASE_URL: %w", err)
	}

	cfg.MaxConns = dbCfg.MaxConns
	cfg.MinConns = dbCfg.MinConns
	cfg.MaxConnLifetime = dbCfg.MaxConnLifetime
	cfg.MaxConnIdleTime = dbCfg.MaxConnIdleTime
	cfg.HealthCheckPeriod = dbCfg.HealthCheckPeriod
	cfg.ConnConfig.Tracer = NewSlowQueryTracer()
	cfg.ConnConfig.ConnectTimeout = dbCfg.ConnectTimeout

	slog.Info("Connecting to database",
		"max_conns", cfg.MaxConns,
		"min_conns", cfg.MinConns,
		"max_conn_lifetime", cfg.MaxConnLifetime,
		"max_conn_idle_time", cfg.MaxConnIdleTime,
		"health_check_period", cfg.HealthCheckPeriod,
		"connect_timeout", cfg.ConnConfig.ConnectTimeout,
	)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, dbCfg.ConnectTimeout)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	slog.Info("Database connection pool established",
		"max_conns", cfg.MaxConns,
		"min_conns", cfg.MinConns,
	)

	return pool, nil
}

// LogPoolStats emits a structured log line with current pool statistics.
// Intended for periodic health monitoring (e.g. called from a background goroutine).
func LogPoolStats(pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	stats := pool.Stat()
	slog.Info("Connection pool stats",
		"total_conns", stats.TotalConns(),
		"idle_conns", stats.IdleConns(),
		"acquired_conns", stats.AcquiredConns(),
		"max_conns", stats.MaxConns(),
	)
}
