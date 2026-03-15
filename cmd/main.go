package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go-net-http-auth-base/internal/env"
	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/infra"
	"go-net-http-auth-base/internal/logger"
	"go-net-http-auth-base/postgres"

	"github.com/joho/godotenv"
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

func main() {
	err := godotenv.Load()
	logger.Setup()

	if err != nil && os.Getenv("API_ENV") != "production" {
		slog.Warn("Warning: .env file not found or failed to load")
	}

	ctx, stopBackgroundTasks := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stopBackgroundTasks()

	pool, err := postgres.NewConnectionPool(ctx)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Initialize and run Partition Manager
	partitionManager := infra.NewAuditLogsPartitionManager(pool)
	if err := partitionManager.RunMaintenance(ctx); err != nil {
		slog.Error("Failed to initialize audit log partitions", "error", err)
		os.Exit(1)
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

	// Log pool stats periodically for health monitoring — stops on shutdown signal.
	runEvery(
		ctx, &wg,
		env.GetEnvAsDuration("DB_STATS_LOG_INTERVAL", 30*time.Second),
		func() {
			postgres.LogPoolStats(pool)
		},
	)

	mux := http.NewServeMux()
	factories.UsersFactory(pool).RegisterRoutes(mux)
	factories.AuthFactory(pool).RegisterRoutes(mux)
	factories.HealthFactory(pool).RegisterRoutes(mux)
	factories.AuditFactory(pool).RegisterRoutes(mux)

	rateLimitMiddleware := factories.RateLimitFactory()
	corsMiddleware := factories.CORSFactory()
	loggerMiddleware := factories.LoggerFactory()
	requestIDMiddleware := factories.RequestUUIDFactory()
	requestContextDataMiddleware := factories.RequestContextDataFactory()
	handler := requestContextDataMiddleware.Use(
		requestIDMiddleware.Use(
			loggerMiddleware.Use(
				corsMiddleware.Use(
					rateLimitMiddleware.Use(
						mux,
					),
				),
			),
		),
	)

	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	go func() {
		slog.Info("Server listening on port :" + port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Block until a shutdown signal is received via ctx.
	<-ctx.Done()

	slog.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Drain HTTP and wait for background goroutines concurrently,
	// both bounded by the same 10-second shutdown window.
	var shutdownWg sync.WaitGroup

	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		wg.Wait()
	}()

	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server forced to shutdown", "error", err)
		}
	}()

	shutdownWg.Wait()

	slog.Info("Server exited gracefully")
}
