package middlewares_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
)

func getTestRoleMiddleware() (middlewares.HandlerMiddleware, *mocks.UsersServiceMock) {
	serviceMock := new(mocks.UsersServiceMock)
	middleware := middlewares.NewRoleMiddleware(
		serviceMock,
		[]domain.UserRole{domain.RoleAdmin},
	)

	return middleware, serviceMock
}

func TestNewRoleMiddleware(t *testing.T) {
	t.Run("should create new role  middleware", func(t *testing.T) {
		middleware := middlewares.NewRoleMiddleware(
			new(mocks.UsersServiceMock),
			[]domain.UserRole{},
		)
		assert.NotNil(t, middleware)
	})
}

func TestRoleMiddleware_Use(t *testing.T) {
	t.Run("should allow access to users with the required role", func(t *testing.T) {
		middleware, serviceMock := getTestRoleMiddleware()

		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx,
			api.RequestContextDataKey,
			&api.RequestContextData{
				UserUUID: "test-uuid",
			},
		)
		req = req.WithContext(ctx)

		serviceMock.On("GetByUUID", "test-uuid").Return(&domain.User{
			UUID: "test-uuid",
			Role: domain.RoleAdmin,
		}, nil)

		rr := httptest.NewRecorder()
		handler := middleware.Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotContains(t, rr.Body.String(), "auth.forbidden")
	})

	t.Run("should deny access to users without the required role", func(t *testing.T) {
		middleware, serviceMock := getTestRoleMiddleware()

		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx,
			api.RequestContextDataKey,
			&api.RequestContextData{
				UserUUID: "test-uuid",
			},
		)
		req = req.WithContext(ctx)

		serviceMock.On("GetByUUID", "test-uuid").Return(&domain.User{
			UUID: "test-uuid",
			Role: domain.RoleUser,
		}, nil)

		rr := httptest.NewRecorder()
		handler := middleware.Use(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "auth.forbidden")
	})
}
