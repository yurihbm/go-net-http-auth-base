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
	var serveWithData func(role domain.UserRole) (*httptest.ResponseRecorder, *shared.RequestContextData)
	serve := func(role domain.UserRole) *httptest.ResponseRecorder {
		rr, _ := serveWithData(role)
		return rr
	}

	serveWithData = func(role domain.UserRole) (*httptest.ResponseRecorder, *shared.RequestContextData) {
		req := httptest.NewRequest("GET", "/", nil)
		data := &shared.RequestContextData{
			UserUUID: "test-uuid",
			UserRole: role,
		}
		ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, data)
		rr := httptest.NewRecorder()
		getTestRoleMiddleware().Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		).ServeHTTP(rr, req.WithContext(ctx))
		return rr, data
	}

	t.Run("should allow access to users with the required role", func(t *testing.T) {
		rr := serve(domain.RoleAdmin)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotContains(t, rr.Body.String(), "auth.forbidden")
	})

	t.Run("should deny access to users without the required role", func(t *testing.T) {
		rr := serve(domain.RoleUser)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.JSONEq(t, `{"data":null,"error":"auth.forbidden"}`, rr.Body.String())
	})

	t.Run("error - records the forbidden error when denying access", func(t *testing.T) {
		_, data := serveWithData(domain.RoleUser)

		var forbiddenErr *domain.ForbiddenError
		assert.ErrorAs(t, data.Error, &forbiddenErr)
		assert.EqualError(t, data.Error, "auth.forbidden")
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
