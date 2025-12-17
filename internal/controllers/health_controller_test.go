package controllers_test

import (
	"context"
	"encoding/json"
	"errors"
	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockPinger struct {
	mock.Mock
}

func (m *MockPinger) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestHealthController_RegisterRoutes(t *testing.T) {
	mockDb := new(MockPinger)
	controller := controllers.NewHealthController(mockDb)
	router := http.NewServeMux()

	controller.RegisterRoutes(router)

	// Verify routes are registered
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/health"},
		{"GET", "/ready"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		_, pattern := router.Handler(req)
		assert.NotEmpty(t, pattern)
	}
}

func TestHealthController_Health(t *testing.T) {
	mockDb := new(MockPinger)
	controller := controllers.NewHealthController(mockDb)

	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	controller.Health(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response api.ResponseBody[string]
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "OK", response.Data)
}

func TestHealthController_Ready(t *testing.T) {
	t.Run("database is ready", func(t *testing.T) {
		mockDb := new(MockPinger)
		mockDb.On("Ping", mock.Anything).Return(nil)
		
		controller := controllers.NewHealthController(mockDb)

		req, _ := http.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		controller.Ready(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response api.ResponseBody[string]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "OK", response.Data)
		mockDb.AssertExpectations(t)
	})

	t.Run("database is not ready", func(t *testing.T) {
		mockDb := new(MockPinger)
		mockDb.On("Ping", mock.Anything).Return(errors.New("connection refused"))
		
		controller := controllers.NewHealthController(mockDb)

		req, _ := http.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		controller.Ready(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		
		var response api.ResponseBody[string]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Database not ready", response.Error)
		mockDb.AssertExpectations(t)
	})
}
