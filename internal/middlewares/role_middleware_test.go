package middlewares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/shared"

	"github.com/stretchr/testify/assert"
)

func getTestRoleMiddleware() middlewares.HandlerMiddleware {
	return middlewares.NewRoleMiddleware([]domain.UserRole{domain.RoleAdmin})
}

func TestNewRoleMiddleware(t *testing.T) {
	t.Run("should create new role  middleware", func(t *testing.T) {
		middleware := middlewares.NewRoleMiddleware([]domain.UserRole{})
		assert.NotNil(t, middleware)
	})
}

func TestRoleMiddleware_Use(t *testing.T) {
	serve := func(role domain.UserRole) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(),
			shared.RequestContextDataKey,
			&shared.RequestContextData{
				UserUUID: "test-uuid",
				UserRole: role,
			},
		)
		rr := httptest.NewRecorder()
		getTestRoleMiddleware().Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		).ServeHTTP(rr, req.WithContext(ctx))
		return rr
	}

	t.Run("should allow access to users with the required role", func(t *testing.T) {
		rr := serve(domain.RoleAdmin)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotContains(t, rr.Body.String(), "auth.forbidden")
	})

	t.Run("should deny access to users without the required role", func(t *testing.T) {
		rr := serve(domain.RoleUser)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "auth.forbidden")
	})

	t.Run("should deny access when the token carries no role", func(t *testing.T) {
		rr := serve("")

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "auth.forbidden")
	})

	t.Run("should return internal server error when request context data is missing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		rr := httptest.NewRecorder()
		getTestRoleMiddleware().Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
