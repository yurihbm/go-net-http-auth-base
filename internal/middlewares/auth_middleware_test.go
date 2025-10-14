package middlewares_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func getTestAuthMiddleware() (*middlewares.AuthMiddleware, *mocks.AuthServiceMock) {
	serviceMock := new(mocks.AuthServiceMock)
	middleware := middlewares.NewAuthMiddleware(serviceMock)

	return middleware, serviceMock
}

func TestNewAuthMiddleware(t *testing.T) {
	t.Run("should create new auth middleware", func(t *testing.T) {
		serviceMock := new(mocks.AuthServiceMock)
		middleware := middlewares.NewAuthMiddleware(serviceMock)

		assert.NotNil(t, middleware)
	})
}

func TestAuthMiddlewareUse(t *testing.T) {
	t.Run("success - valid token", func(t *testing.T) {
		middleware, serviceMock := getTestAuthMiddleware()
		userUUID := "test-user-uuid"
		token := "valid-token"

		serviceMock.On("VerifyToken", token).Return(userUUID, nil)

		// Create a test handler that will be wrapped by the middleware
		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			// Verify that the user UUID was added to the context
			contextUserUUID := r.Context().Value(middlewares.UserUUIDKey)
			assert.Equal(t, userUUID, contextUserUUID)
			w.WriteHeader(http.StatusOK)
		})

		// Wrap the handler with middleware
		wrappedHandler := middleware.Use(nextHandler)

		// Create request with authorization header
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		// Execute the handler
		wrappedHandler.ServeHTTP(w, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "VerifyToken", token)
	})

	t.Run("unauthorized - missing authorization header", func(t *testing.T) {
		middleware, serviceMock := getTestAuthMiddleware()

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		// No Authorization header set
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "auth.unauthorized", response.Message)
		assert.Equal(t, "missing authorization header", response.Error)
		serviceMock.AssertNotCalled(t, "VerifyToken", mock.Anything)
	})

	t.Run("unauthorized - invalid token format (missing Bearer prefix)", func(t *testing.T) {
		middleware, serviceMock := getTestAuthMiddleware()

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "InvalidTokenFormat")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "auth.unauthorized", response.Message)
		assert.Equal(t, "invalid token format", response.Error)
		serviceMock.AssertNotCalled(t, "VerifyToken", mock.Anything)
	})

	t.Run("unauthorized - token verification fails", func(t *testing.T) {
		middleware, serviceMock := getTestAuthMiddleware()
		token := "invalid-token"
		errTokenExpired := errors.New("token expired")

		serviceMock.On("VerifyToken", token).Return("", errTokenExpired)

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "auth.unauthorized", response.Message)
		assert.Equal(t, "token expired", response.Error)
		serviceMock.AssertCalled(t, "VerifyToken", token)
	})

	t.Run("unauthorized - empty token after Bearer prefix", func(t *testing.T) {
		middleware, serviceMock := getTestAuthMiddleware()

		// Mock the VerifyToken call with empty string to return error
		serviceMock.On("VerifyToken", "").Return("", errors.New("invalid token"))

		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
		})

		wrappedHandler := middleware.Use(nextHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer ")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		assert.False(t, handlerCalled)
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "auth.unauthorized", response.Message)
		assert.Equal(t, "invalid token", response.Error)
		// VerifyToken should still be called with empty string
		serviceMock.AssertCalled(t, "VerifyToken", "")
	})

	t.Run("success - multiple requests with different tokens", func(t *testing.T) {
		middleware, serviceMock := getTestAuthMiddleware()

		token1 := "token-1"
		userUUID1 := "user-uuid-1"
		token2 := "token-2"
		userUUID2 := "user-uuid-2"

		serviceMock.On("VerifyToken", token1).Return(userUUID1, nil).Once()
		serviceMock.On("VerifyToken", token2).Return(userUUID2, nil).Once()

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := middleware.Use(nextHandler)

		// First request
		req1 := httptest.NewRequest("GET", "/test", nil)
		req1.Header.Set("Authorization", "Bearer "+token1)
		w1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Second request
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.Header.Set("Authorization", "Bearer "+token2)
		w2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)

		serviceMock.AssertNumberOfCalls(t, "VerifyToken", 2)
	})
}
