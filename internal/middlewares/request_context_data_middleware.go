package middlewares

import (
	"context"
	"net/http"

	"go-net-http-auth-base/internal/api"
)

type RequestContextDataMiddleware struct{}

func NewRequestContextDataMiddleware() GlobalMiddleware {
	return &RequestContextDataMiddleware{}
}

func (m *RequestContextDataMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqContextData := &api.RequestContextData{}
		ctx := context.WithValue(r.Context(), api.RequestContextDataKey, reqContextData)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
