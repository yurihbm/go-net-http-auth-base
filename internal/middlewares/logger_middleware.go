package middlewares

import (
	"context"
	"go-net-http-auth-base/internal/api"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type LoggerMiddleware struct{}

func NewLoggerMiddleware() *LoggerMiddleware {
	return &LoggerMiddleware{}
}

func (m *LoggerMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		reqContextData := &api.RequestContextData{
			RequestID: uuid.New().String(),
		}
		ctx := context.WithValue(r.Context(), api.RequestContextDataKey, reqContextData)

		next.ServeHTTP(ww, r.WithContext(ctx))

		duration := time.Since(start)

		level := slog.LevelInfo
		if ww.statusCode >= 500 {
			level = slog.LevelError
		} else if ww.statusCode >= 400 {
			level = slog.LevelWarn
		}

		attrs := []slog.Attr{
			slog.String("requestID", reqContextData.RequestID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", ww.statusCode),
			slog.Duration("duration", duration),
			slog.String("ip", r.RemoteAddr),
			slog.String("userAgent", r.UserAgent()),
		}
		if reqContextData.UserUUID != "" {
			attrs = append(attrs, slog.String("userUUID", reqContextData.UserUUID))
		}
		if reqContextData.Error != nil {
			attrs = append(attrs, slog.String("error", reqContextData.Error.Error()))
		}

		slog.LogAttrs(r.Context(), level, "HTTP Request", attrs...)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
