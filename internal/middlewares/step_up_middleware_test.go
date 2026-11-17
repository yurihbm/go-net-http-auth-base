package middlewares_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/shared"

	"github.com/stretchr/testify/assert"
)

func TestStepUpMiddleware_Use(t *testing.T) {
	newRequest := func(data *shared.RequestContextData) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/users/me/email", nil)
		if data == nil {
			return req
		}
		return req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, data))
	}
	session := &shared.RequestContextData{UserUUID: "user-uuid", SessionUUID: "session-uuid"}

	t.Run("success - elevated session reaches the handler", func(t *testing.T) {
		checker := new(mocks.StepUpServiceMock)
		checker.On("IsElevated", "user-uuid", "session-uuid").Return(true, nil).Once()
		called := false
		handler := middlewares.NewStepUpMiddleware(checker).Use(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		})

		w := httptest.NewRecorder()
		handler(w, newRequest(session))

		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("error - not elevated", func(t *testing.T) {
		checker := new(mocks.StepUpServiceMock)
		checker.On("IsElevated", "user-uuid", "session-uuid").Return(false, nil).Once()
		called := false
		handler := middlewares.NewStepUpMiddleware(checker).Use(func(w http.ResponseWriter, r *http.Request) { called = true })

		w := httptest.NewRecorder()
		handler(w, newRequest(session))

		var response api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, "auth.stepUp.required", response.Error)
		assert.False(t, called)
	})

	t.Run("error - checker failure", func(t *testing.T) {
		checker := new(mocks.StepUpServiceMock)
		checker.On("IsElevated", "user-uuid", "session-uuid").Return(false, errors.New("db down")).Once()
		called := false
		handler := middlewares.NewStepUpMiddleware(checker).Use(func(w http.ResponseWriter, r *http.Request) { called = true })

		w := httptest.NewRecorder()
		handler(w, newRequest(session))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.False(t, called)
	})

	t.Run("error - missing request context data", func(t *testing.T) {
		checker := new(mocks.StepUpServiceMock)
		called := false
		handler := middlewares.NewStepUpMiddleware(checker).Use(func(w http.ResponseWriter, r *http.Request) { called = true })

		w := httptest.NewRecorder()
		handler(w, newRequest(nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.False(t, called)
		checker.AssertNotCalled(t, "IsElevated", "", "")
	})
}
