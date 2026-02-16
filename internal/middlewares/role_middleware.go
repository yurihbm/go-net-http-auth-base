package middlewares

import (
	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"net/http"
	"slices"
)

type RoleMiddleware struct {
	usersService domain.UsersService
	roles        []domain.UserRole
}

var _ HandlerMiddleware = (*RoleMiddleware)(nil)

func NewRoleMiddleware(usersService domain.UsersService, roles []domain.UserRole) HandlerMiddleware {
	return &RoleMiddleware{usersService, roles}
}

func (m *RoleMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if reqCtxData, ok := r.Context().Value(api.RequestContextDataKey).(*api.RequestContextData); ok {
			// TODO: Use token payload instead of fetching user from database when
			// required info is included in the token
			user, err := m.usersService.GetByUUID(reqCtxData.UserUUID)

			if err == nil && slices.Contains(m.roles, user.Role) {
				next.ServeHTTP(w, r)
				return
			}
		}

		api.WriteJSONResponse(w, http.StatusForbidden, api.ResponseBody[any]{
			Message: "auth.forbidden",
			Error:   "user does not have access to this resource",
		})
	}
}
