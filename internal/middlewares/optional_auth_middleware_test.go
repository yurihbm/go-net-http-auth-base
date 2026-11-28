package middlewares_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/shared"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func getTestOptionalAuthMiddleware() (middlewares.HandlerMiddleware, *mocks.TokenVerifierMock) {
	serviceMock := new(mocks.TokenVerifierMock)
	return middlewares.NewOptionalAuthMiddleware(serviceMock), serviceMock
}

func TestNewOptionalAuthMiddleware(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		middleware := middlewares.NewOptionalAuthMiddleware(new(mocks.TokenVerifierMock))

		assert.NotNil(t, middleware)
	})
}

func TestOptionalAuthMiddleware_Use(t *testing.T) {
	newRequest := func(reqContextData *shared.RequestContextData, token string) *http.Request {
		req := httptest.NewRequest("GET", "/test", nil)
		if token != "" {
			req.AddCookie(&http.Cookie{Name: api.AccessTokenCookieName, Value: token})
		}
		ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, reqContextData)
		return req.WithContext(ctx)
	}

	t.Run("success - valid token fills the request context data", func(t *testing.T) {
		middleware, serviceMock := getTestOptionalAuthMiddleware()
		serviceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    "valid-token",
			Audience: domain.TokenAudienceAccess,
		}).Return(&domain.VerifiedTokenData{
			Subject:   "test-user-uuid",
			SessionID: "test-session-uuid",
			Role:      domain.RoleUser,
		}, nil)
		reqContextData := &shared.RequestContextData{}
		handlerCalled := false
		handler := middleware.Use(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, newRequest(reqContextData, "valid-token"))

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "test-user-uuid", reqContextData.UserUUID)
		assert.Equal(t, domain.RoleUser, reqContextData.UserRole)
		assert.Equal(t, "test-session-uuid", reqContextData.SessionUUID)
	})

	t.Run("success - missing access token cookie continues as anonymous", func(t *testing.T) {
		middleware, serviceMock := getTestOptionalAuthMiddleware()
		reqContextData := &shared.RequestContextData{}
		handlerCalled := false
		handler := middleware.Use(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, newRequest(reqContextData, ""))

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, reqContextData.UserUUID)
		assert.Empty(t, reqContextData.UserRole)
		assert.Empty(t, reqContextData.SessionUUID)
		serviceMock.AssertNotCalled(t, "VerifyToken", mock.Anything)
	})

	t.Run("error - invalid token is unauthorized instead of anonymous", func(t *testing.T) {
		middleware, serviceMock := getTestOptionalAuthMiddleware()
		serviceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    "expired-token",
			Audience: domain.TokenAudienceAccess,
		}).Return(nil, errors.New("token expired"))
		reqContextData := &shared.RequestContextData{}
		handlerCalled := false
		handler := middleware.Use(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, newRequest(reqContextData, "expired-token"))

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var response api.ResponseBody[any]
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "auth.unauthorized", response.Error)
		assert.Empty(t, reqContextData.UserUUID)
	})
}
