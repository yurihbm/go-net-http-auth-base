package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func spanContext() trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
	})
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	return out
}

func TestTraceContextHandler_Handle(t *testing.T) {
	t.Run("adds trace_id and span_id when span in context", func(t *testing.T) {
		var buf bytes.Buffer
		l := slog.New(&traceContextHandler{inner: slog.NewJSONHandler(&buf, nil)})
		ctx := trace.ContextWithSpanContext(context.Background(), spanContext())

		l.InfoContext(ctx, "hello")

		out := decode(t, &buf)
		assert.Equal(t, spanContext().TraceID().String(), out["trace_id"])
		assert.Equal(t, spanContext().SpanID().String(), out["span_id"])
	})

	t.Run("unchanged output without span", func(t *testing.T) {
		var plain, wrapped bytes.Buffer
		opts := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}}
		slog.New(slog.NewJSONHandler(&plain, opts)).Info("hello", "k", "v")
		slog.New(&traceContextHandler{inner: slog.NewJSONHandler(&wrapped, opts)}).InfoContext(context.Background(), "hello", "k", "v")

		assert.Equal(t, plain.String(), wrapped.String())
	})

	t.Run("WithAttrs and WithGroup keep the wrapper", func(t *testing.T) {
		var buf bytes.Buffer
		h := &traceContextHandler{inner: slog.NewJSONHandler(&buf, nil)}

		withAttrs := h.WithAttrs([]slog.Attr{slog.String("a", "b")})
		withGroup := withAttrs.WithGroup("g")

		assert.IsType(t, &traceContextHandler{}, withAttrs)
		assert.IsType(t, &traceContextHandler{}, withGroup)

		ctx := trace.ContextWithSpanContext(context.Background(), spanContext())
		slog.New(withAttrs).InfoContext(ctx, "hello")
		out := decode(t, &buf)
		assert.Equal(t, "b", out["a"])
		assert.Equal(t, spanContext().TraceID().String(), out["trace_id"])
	})
}

func TestSetup(t *testing.T) {
	t.Run("fans out to stdout and extra handler", func(t *testing.T) {
		previous := slog.Default()
		t.Cleanup(func() { slog.SetDefault(previous) })
		var buf bytes.Buffer
		extra := &captureHandler{}

		slog.SetDefault(slog.New(newHandler(&buf, true, extra)))
		slog.Info("hello")

		assert.Contains(t, buf.String(), "hello")
		require.Len(t, extra.records, 1)
		assert.Equal(t, "hello", extra.records[0].Message)
	})

	t.Run("stdout only without extra", func(t *testing.T) {
		var buf bytes.Buffer
		h := newHandler(&buf, false)

		assert.IsType(t, &traceContextHandler{}, h)
		slog.New(h).Info("hello")
		assert.Contains(t, buf.String(), "hello")
	})
}
