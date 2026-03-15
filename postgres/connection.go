package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go-net-http-auth-base/internal/env"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxConns          = int32(25)
	defaultMinConns          = int32(5)
	defaultMaxConnLifetime   = time.Hour
	defaultMaxConnIdleTime   = 30 * time.Minute
	defaultHealthCheckPeriod = time.Minute
	defaultConnectTimeout    = 15 * time.Second
)

// PoolConfig holds connection pool settings parsed from environment variables.
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}

// NewPoolConfig reads pool settings from environment variables with sensible defaults.
//
// Environment variables:
//   - DB_MAX_CONNS:           maximum number of pool connections (default: 25)
//   - DB_MIN_CONNS:           minimum number of idle pool connections (default: 5)
//   - DB_MAX_CONN_LIFETIME:   max duration a connection may be reused (default: 1h)
//   - DB_MAX_CONN_IDLE_TIME:  max duration a connection may be idle (default: 30m)
//   - DB_HEALTH_CHECK_PERIOD: interval between health-check pings (default: 1m)
//   - DB_CONNECT_TIMEOUT:     timeout for the initial ping on startup (default: 15s)
//
// MinConns is capped to MaxConns if it would otherwise exceed it.
func NewPoolConfig() PoolConfig {
	cfg := PoolConfig{
		MaxConns:          env.GetEnvAsInt32("DB_MAX_CONNS", defaultMaxConns),
		MinConns:          env.GetEnvAsInt32("DB_MIN_CONNS", defaultMinConns),
		MaxConnLifetime:   env.GetEnvAsDuration("DB_MAX_CONN_LIFETIME", defaultMaxConnLifetime),
		MaxConnIdleTime:   env.GetEnvAsDuration("DB_MAX_CONN_IDLE_TIME", defaultMaxConnIdleTime),
		HealthCheckPeriod: env.GetEnvAsDuration("DB_HEALTH_CHECK_PERIOD", defaultHealthCheckPeriod),
		ConnectTimeout:    env.GetEnvAsDuration("DB_CONNECT_TIMEOUT", defaultConnectTimeout),
	}

	if cfg.MinConns > cfg.MaxConns {
		cfg.MinConns = cfg.MaxConns
	}

	return cfg
}

// NewConnectionPool creates a pgxpool.Pool using DATABASE_URL and pool config
// from environment variables. The caller is responsible for closing the pool.
// The provided context controls the initial connection and ping timeout.
// All structured log output goes to slog.Default(), which is configured at
// application startup via logger.Setup().
func NewConnectionPool(ctx context.Context) (*pgxpool.Pool, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL not set in environment")
	}

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DATABASE_URL: %w", err)
	}

	poolCfg := NewPoolConfig()
	cfg.MaxConns = poolCfg.MaxConns
	cfg.MinConns = poolCfg.MinConns
	cfg.MaxConnLifetime = poolCfg.MaxConnLifetime
	cfg.MaxConnIdleTime = poolCfg.MaxConnIdleTime
	cfg.HealthCheckPeriod = poolCfg.HealthCheckPeriod
	cfg.ConnConfig.Tracer = NewSlowQueryTracer()
	cfg.ConnConfig.ConnectTimeout = poolCfg.ConnectTimeout

	slog.Info("Connecting to database",
		"max_conns", cfg.MaxConns,
		"min_conns", cfg.MinConns,
		"max_conn_lifetime", cfg.MaxConnLifetime,
		"max_conn_idle_time", cfg.MaxConnIdleTime,
		"health_check_period", cfg.HealthCheckPeriod,
		"connect_timeout", poolCfg.ConnectTimeout,
	)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, poolCfg.ConnectTimeout)
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
