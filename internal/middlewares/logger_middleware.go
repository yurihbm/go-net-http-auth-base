package middlewares

import (
	"log/slog"
	"net/http"
	"time"

	"go-net-http-auth-base/internal/api"
)

type LoggerMiddleware struct{}

func NewLoggerMiddleware() GlobalMiddleware {
	return &LoggerMiddleware{}
}

func (m *LoggerMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		duration := time.Since(start)

		var reqContextData *api.RequestContextData
		if val := r.Context().Value(api.RequestContextDataKey); val != nil {
			reqContextData = val.(*api.RequestContextData)
		}

		level := slog.LevelInfo
		if ww.statusCode >= 500 {
			level = slog.LevelError
		} else if ww.statusCode >= 400 {
			level = slog.LevelWarn
		}

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", ww.statusCode),
			slog.Duration("duration", duration),
			slog.String("ip", r.RemoteAddr),
			slog.String("userAgent", r.UserAgent()),
		}

		if reqContextData != nil {
			if reqContextData.RequestUUID != "" {
				attrs = append(attrs, slog.String("requestUUID", reqContextData.RequestUUID))
			}
			if reqContextData.UserUUID != "" {
				attrs = append(attrs, slog.String("userUUID", reqContextData.UserUUID))
			}
			if reqContextData.Error != nil {
				attrs = append(attrs, slog.String("error", reqContextData.Error.Error()))
			}
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
