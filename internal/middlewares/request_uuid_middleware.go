package middlewares

import (
	"net/http"

	"go-net-http-auth-base/internal/api"

	"github.com/google/uuid"
)

type RequestUUIDMiddleware struct{}

func NewRequestUUIDMiddleware() *RequestUUIDMiddleware {
	return &RequestUUIDMiddleware{}
}

func (m *RequestUUIDMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestUUID := uuid.New().String()

		var reqContextData *api.RequestContextData
		if val := r.Context().Value(api.RequestContextDataKey); val != nil {
			reqContextData = val.(*api.RequestContextData)
			reqContextData.RequestUUID = requestUUID

			// Add to response header
			w.Header().Set("X-Request-UUID", requestUUID)
		}

		next.ServeHTTP(w, r)
	})
}
