package logger

import (
	"context"
	"io"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel/trace"
)

type traceContextHandler struct {
	inner slog.Handler
}

func (h *traceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *traceContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.inner.Handle(ctx, r)
}

func (h *traceContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceContextHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *traceContextHandler) WithGroup(name string) slog.Handler {
	return &traceContextHandler{inner: h.inner.WithGroup(name)}
}

func newHandler(w io.Writer, isProduction bool, extra ...slog.Handler) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	var stdout slog.Handler
	if isProduction {
		stdout = slog.NewJSONHandler(w, opts)
	} else {
		stdout = slog.NewTextHandler(w, opts)
	}

	handler := &traceContextHandler{inner: stdout}
	if len(extra) == 0 {
		return handler
	}
	return slog.NewMultiHandler(append([]slog.Handler{handler}, extra...)...)
}

// Setup configures the global logger based on the environment.
// If isProduction is true, it uses a JSON handler.
// Otherwise, it uses a Text handler.
// Extra handlers receive every record in addition to stdout.
func Setup(isProduction bool, extra ...slog.Handler) {
	slog.SetDefault(slog.New(newHandler(os.Stdout, isProduction, extra...)))
}
