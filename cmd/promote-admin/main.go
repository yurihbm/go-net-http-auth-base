package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/commands"
	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/logger"
	"go-net-http-auth-base/postgres"

	"github.com/joho/godotenv"
)

func main() {
	os.Exit(run())
}

func run() int {
	err := godotenv.Load()

	logger.Setup(os.Getenv("API_ENV") == "production")

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		slog.Error("Failed to load configuration", "error", cfgErr)
		return 1
	}

	if err != nil && !cfg.IsProduction() {
		slog.Warn("Warning: .env file not found or failed to load")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewConnectionPool(ctx, cfg.Database)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		return 1
	}
	defer pool.Close()

	deps, err := factories.NewDependencies(pool, cfg)
	if err != nil {
		slog.Error("Failed to initialize application dependencies", "error", err)
		return 1
	}

	if err := commands.PromoteAdmin(ctx, deps.UsersService, deps.AuditService, os.Stdout, os.Args[1:]); err != nil {
		slog.Error("Failed to promote admin", "error", err)
		return 1
	}
	return 0
}
