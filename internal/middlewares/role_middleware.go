package middlewares

import (
	"errors"
	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
	"net/http"
	"slices"
)

type RoleMiddleware struct {
	roles []domain.UserRole
}

var _ HandlerMiddleware = (*RoleMiddleware)(nil)

func NewRoleMiddleware(roles []domain.UserRole) HandlerMiddleware {
	return &RoleMiddleware{roles}
}

func (m *RoleMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqCtxData, ok := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData)
		if !ok {
			// Missing context data means AuthMiddleware did not run — a wiring
			// bug, not an authorization failure.
			api.HandleError(r.Context(), w, errors.New("request context data is missing"))
			return
		}

		if slices.Contains(m.roles, reqCtxData.UserRole) {
			next.ServeHTTP(w, r)
			return
		}

		api.WriteJSONResponse(w, http.StatusForbidden, api.ResponseBody[any]{
			Message: "auth.forbidden",
			Error:   "user does not have access to this resource",
		})
	}
}
