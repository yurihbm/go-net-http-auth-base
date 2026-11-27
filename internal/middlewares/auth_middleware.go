package middlewares

import (
	"fmt"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
)

type AuthMiddleware struct {
	tokenVerifier domain.TokenVerifier
}

var _ HandlerMiddleware = (*AuthMiddleware)(nil)

func NewAuthMiddleware(tokenVerifier domain.TokenVerifier) HandlerMiddleware {
	return &AuthMiddleware{tokenVerifier: tokenVerifier}
}

func (m *AuthMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := r.Cookie(api.AccessTokenCookieName)
		if err != nil {
			api.HandleError(r.Context(), w, errUnauthorized(err))
			return
		}

		tokenData, err := m.tokenVerifier.VerifyToken(r.Context(), domain.VerifyTokenDTO{
			Token:    accessToken.Value,
			Audience: domain.TokenAudienceAccess,
		})
		if err != nil {
			api.HandleError(r.Context(), w, errUnauthorized(err))
			return
		}

		if reqContextData, ok := r.Context().Value(
			shared.RequestContextDataKey,
		).(*shared.RequestContextData); ok {
			reqContextData.UserUUID = tokenData.Subject
			reqContextData.UserRole = tokenData.Role
			reqContextData.SessionUUID = tokenData.SessionID
		}

		next.ServeHTTP(w, r)
	}
}

func errUnauthorized(cause error) error {
	return fmt.Errorf("%w: %w", domain.NewUnauthorizedError("auth.unauthorized"), cause)
}
