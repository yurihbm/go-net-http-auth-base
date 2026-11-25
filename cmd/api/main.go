package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/infra"
	"go-net-http-auth-base/internal/logger"
	"go-net-http-auth-base/internal/telemetry"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"go.opentelemetry.io/contrib/bridges/otelslog"
)

// The write timeout leaves room for the OAuth callback, whose provider calls
// time out after 10 seconds.
const (
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 15 * time.Second
	serverWriteTimeout      = 30 * time.Second
	serverIdleTimeout       = 60 * time.Second

	expiredRecordsSweepInterval = time.Hour
)

// runEvery runs fn on every interval tick until ctx is cancelled.
// It increments wg before starting and decrements it when done.
func runEvery(ctx context.Context, wg *sync.WaitGroup, interval time.Duration, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fn()
			}
		}
	}()
}

// @title			Go net/http Auth Base API
// @version		1.0
// @description	REST API for user authentication and user management.
// @description	Authenticated endpoints need the `access_token` cookie set by `POST /auth/login`. Swagger 2.0 cannot describe cookie auth, so endpoints are not marked as secured here; "Try it out" works because the browser sends the cookie.
// @BasePath		/
func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() (runErr error) {
	err := godotenv.Load()

	// Single os.Getenv call before config.Load, so config errors can be logged properly.
	logger.Setup(os.Getenv("API_ENV") == "production")

	// Logs the failure before flushing telemetry, so it is also exported over OTLP.
	var tel *telemetry.Telemetry
	defer func() {
		if runErr != nil {
			slog.Error("Application failed", "error", runErr)
		}
		if tel == nil {
			return
		}

		telemetryCtx, cancelTelemetry := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelTelemetry()

		if err := tel.Shutdown(telemetryCtx); err != nil {
			slog.Error("Failed to shutdown telemetry", "error", err)
		}
	}()

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		return fmt.Errorf("load configuration: %w", cfgErr)
	}

	if err != nil && !cfg.IsProduction() {
		slog.Warn("Warning: .env file not found or failed to load")
	}

	ctx, stopBackgroundTasks := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stopBackgroundTasks()

	tel, err = telemetry.New(ctx, cfg.Telemetry, cfg.Env)
	if err != nil {
		return fmt.Errorf("initialize telemetry: %w", err)
	}

	var dbTracers []pgx.QueryTracer
	if tel.Enabled {
		logger.Setup(
			cfg.IsProduction(),
			otelslog.NewHandler(cfg.Telemetry.ServiceName, otelslog.WithLoggerProvider(tel.LoggerProvider), otelslog.WithSource(true)),
		)

		dbConfig, err := pgx.ParseConfig(cfg.Database.URL)
		if err != nil {
			return fmt.Errorf("parse database URL: %w", err)
		}
		otelQueryTracer, err := postgres.NewOTelQueryTracer(tel.TracerProvider, tel.MeterProvider, dbConfig.Database)
		if err != nil {
			return fmt.Errorf("create database telemetry tracer: %w", err)
		}
		dbTracers = append(dbTracers, otelQueryTracer)
	}

	pool, err := postgres.NewConnectionPool(ctx, cfg.Database, dbTracers...)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	if tel.Enabled {
		poolMetrics, err := postgres.RegisterPoolMetrics(pool, tel.MeterProvider)
		if err != nil {
			return fmt.Errorf("register database pool metrics: %w", err)
		}
		defer func() {
			if err := poolMetrics.Unregister(); err != nil {
				slog.Error("Failed to unregister database pool metrics", "error", err)
			}
		}()
	}

	// Initialize and run Partition Manager
	partitionManager := infra.NewAuditLogsPartitionManager(pool)
	if err := partitionManager.RunMaintenance(ctx); err != nil {
		return fmt.Errorf("initialize audit log partitions: %w", err)
	}

	recordsSweeper := infra.NewExpiredRecordsSweeper(pool)
	if err := recordsSweeper.RunMaintenance(ctx); err != nil {
		slog.Error("Failed to sweep expired records", "error", err)
	}

	var wg sync.WaitGroup

	// Run partition maintenance in background — stops on shutdown signal.
	runEvery(
		ctx, &wg, 24*time.Hour,
		func() {
			if err := partitionManager.RunMaintenance(ctx); err != nil {
				slog.Error("Failed to maintain audit log partitions", "error", err)
			}
		},
	)

	// Sweep expired sessions, challenges, pending sign-ups and email send limits in background — stops on shutdown signal.
	runEvery(
		ctx, &wg, expiredRecordsSweepInterval,
		func() {
			if err := recordsSweeper.RunMaintenance(ctx); err != nil {
				slog.Error("Failed to sweep expired records", "error", err)
			}
		},
	)

	// Log pool stats periodically for health monitoring — stops on shutdown signal.
	runEvery(
		ctx, &wg,
		cfg.DBStatsLogInterval,
		func() {
			postgres.LogPoolStats(pool)
		},
	)

	deps, err := factories.NewDependencies(pool, cfg)
	if err != nil {
		return fmt.Errorf("initialize application dependencies: %w", err)
	}

	handler := factories.NewHandler(ctx, deps, cfg, tel)

	port := cfg.Port

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("Server listening on port :" + port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-serverErr:
		runErr = fmt.Errorf("server failed: %w", err)
		stopBackgroundTasks()
	}

	slog.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	if err := waitGroupWithContext(shutdownCtx, &wg); err != nil {
		slog.Warn("Background tasks did not stop before the shutdown deadline", "error", err)
	}

	slog.Info("Server exited")

	return runErr
}
