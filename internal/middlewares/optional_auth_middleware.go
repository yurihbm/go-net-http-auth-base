package middlewares

import (
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
)

// OptionalAuthMiddleware lets a request without an access token through as
// anonymous. A token that is present is verified like AuthMiddleware does, so
// an expired one is still a 401 and the client refreshes its session.
type OptionalAuthMiddleware struct {
	auth HandlerMiddleware
}

var _ HandlerMiddleware = (*OptionalAuthMiddleware)(nil)

func NewOptionalAuthMiddleware(tokenVerifier domain.TokenVerifier) HandlerMiddleware {
	return &OptionalAuthMiddleware{auth: NewAuthMiddleware(tokenVerifier)}
}

func (m *OptionalAuthMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	authenticated := m.auth.Use(next)

	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(api.AccessTokenCookieName); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		authenticated.ServeHTTP(w, r)
	}
}
