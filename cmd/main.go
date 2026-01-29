package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/infra"
	"go-net-http-auth-base/internal/logger"
	"go-net-http-auth-base/postgres"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	logger.Setup()

	if err != nil && os.Getenv("API_ENV") != "production" {
		slog.Warn("Warning: .env file not found or failed to load")
	}

	ctx := context.Background()
	conn := postgres.NewConnection(ctx)

	// Initialize and run Partition Manager
	partitionManager := infra.NewAuditLogsPartitionManager(conn)
	if err := partitionManager.RunMaintenance(ctx); err != nil {
		slog.Error("Failed to initialize audit log partitions", "error", err)
		os.Exit(1)
	}

	// Run partition maintenance in background
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := partitionManager.RunMaintenance(context.Background()); err != nil {
				slog.Error("Failed to maintain audit log partitions", "error", err)
			}
		}
	}()

	defer func() {
		if err := conn.Close(ctx); err != nil {
			slog.Error("Error closing database connection", "error", err)
		}
	}()

	mux := http.NewServeMux()
	factories.UsersFactory(conn).RegisterRoutes(mux)
	factories.AuthFactory(conn).RegisterRoutes(mux)
	factories.HealthFactory(conn).RegisterRoutes(mux)

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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server exited gracefully")
}
