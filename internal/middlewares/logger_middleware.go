package middlewares

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type LoggerData struct {
	UserUUID  string
	RequestID string
}

type LoggerContextKey string

const LoggerDataKey LoggerContextKey = "loggerData"

type LoggerMiddleware struct{}

func NewLoggerMiddleware() *LoggerMiddleware {
	return &LoggerMiddleware{}
}

func (m *LoggerMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		loggerData := &LoggerData{
			RequestID: uuid.New().String(),
		}
		ctx := context.WithValue(r.Context(), LoggerDataKey, loggerData)

		next.ServeHTTP(ww, r.WithContext(ctx))

		duration := time.Since(start)

		level := slog.LevelInfo
		if ww.statusCode >= 500 {
			level = slog.LevelError
		} else if ww.statusCode >= 400 {
			level = slog.LevelWarn
		}

		attrs := []slog.Attr{
			slog.String("requestID", loggerData.RequestID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", ww.statusCode),
			slog.Duration("duration", duration),
			slog.String("ip", r.RemoteAddr),
			slog.String("userAgent", r.UserAgent()),
		}
		if loggerData.UserUUID != "" {
			attrs = append(attrs, slog.String("userUUID", loggerData.UserUUID))
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
