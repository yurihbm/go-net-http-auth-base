package middlewares

import (
	"context"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
)

type AuthContextKey string

const (
	UserUUIDKey AuthContextKey = "userUUID"
)

type AuthMiddleware struct {
	authService domain.AuthService
}

var _ HandlerMiddleware = (*AuthMiddleware)(nil)

func NewAuthMiddleware(authService domain.AuthService) *AuthMiddleware {
	return &AuthMiddleware{authService: authService}
}

func (m *AuthMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := r.Cookie("access_token")
		if err != nil {
			api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
				Message: "auth.unauthorized",
				Error:   "missing authorization header",
			})
			return
		}

		tokenData, err := m.authService.VerifyToken(domain.VerifyTokenDTO{
			Token:    accessToken.Value,
			Audience: domain.TokenAudienceAccess,
		})
		if err != nil {
			api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
				Message: "auth.unauthorized",
				Error:   err.Error(),
			})
			return
		}

		ctx := context.WithValue(r.Context(), UserUUIDKey, tokenData.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
