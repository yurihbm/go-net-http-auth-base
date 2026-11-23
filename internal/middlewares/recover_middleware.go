package middlewares

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
)

type RecoverMiddleware struct{}

func NewRecoverMiddleware() GlobalMiddleware {
	return &RecoverMiddleware{}
}

func (m *RecoverMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &headerTrackingWriter{ResponseWriter: w}

		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}

			slog.ErrorContext(r.Context(), "panic recovered",
				"panic", fmt.Sprint(v),
				"stack", string(debug.Stack()),
			)

			if !rw.wroteHeader {
				api.HandleError(r.Context(), rw, domain.NewInternalServerError(
					"internalServerError",
					fmt.Errorf("panic: %v", v),
				))
			}
		}()

		next.ServeHTTP(rw, r)
	})
}

type headerTrackingWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *headerTrackingWriter) WriteHeader(code int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *headerTrackingWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

func (w *headerTrackingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
