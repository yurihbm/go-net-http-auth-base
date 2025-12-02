package logger

import (
	"log/slog"
	"os"
)

// Setup configures the global logger based on the environment.
// If env is "production", it uses a JSON handler.
// Otherwise, it uses a Text handler.
func Setup() {
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if os.Getenv("API_ENV") == "production" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}
