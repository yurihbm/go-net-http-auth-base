package logger

import (
	"log/slog"
	"os"
)

// Setup configures the global logger based on the environment.
// If isProduction is true, it uses a JSON handler.
// Otherwise, it uses a Text handler.
func Setup(isProduction bool) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if isProduction {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}
