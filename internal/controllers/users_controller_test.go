package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestUsersController() (*controllers.UsersController, *mocks.UsersServiceMock, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock) {
	serviceMock := new(mocks.UsersServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	middlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.NewUsersController(serviceMock, auditMock, middlewareMock)

	return controller, serviceMock, auditMock, middlewareMock
}

func TestUsersController_RegisterRoutes(t *testing.T) {
	t.Run("should register routes with auth middleware", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, _, authMiddleware := newTestUsersController()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(4)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 4)
	})
}

func TestUsersController_CreateUser(t *testing.T) {
	user := &domain.User{
		UUID:  "test-uuid",
		Name:  "John Doe",
		Email: "john.doe@example.com",
		Role:  domain.RoleUser,
	}
	dto := domain.CreateUserDTO{
		Name:     "John Doe",
		Email:    "john.doe@example.com",
		Password: "password123",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Create", dto).Return(user, nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserCreate &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == user.UUID &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getControllerArgs("POST", "/users/", dto)

		controller.CreateUser(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, response.Data, *user)
		assert.Equal(t, domain.RoleUser, response.Data.Role)
		serviceMock.AssertCalled(t, "Create", dto)
		auditMock.AssertExpectations(t)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := getControllerArgs(
			"POST",
			"/users/",
			domain.CreateUserDTO{
				Name:     "John Doe",
				Email:    "john@mail.com",
				Password: "1234556",
			},
		)

		controller.CreateUser(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertNotCalled(t, "Create")
		auditMock.AssertNotCalled(t, "Log")
	})

	t.Run("short password", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := getControllerArgs(
			"POST",
			"/users/",
			struct{ Test string }{
				Test: "invalid",
			},
		)

		controller.CreateUser(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Create")
		auditMock.AssertNotCalled(t, "Log")
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Create", dto).Return(nil, assert.AnError)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserCreate &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

		w, req := getControllerArgs("POST", "/users/", dto)

		controller.CreateUser(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Create", dto)
		auditMock.AssertExpectations(t)
	})
}

func TestUsersController_GetMe(t *testing.T) {
	user := &domain.User{
		UUID:  "test-uuid",
		Name:  "John Doe",
		Email: "john.doe@example.com",
		Role:  domain.RoleUser,
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("GetByUUID", "test-uuid").Return(user, nil)

		w, req := getControllerArgs("GET", "/users/me", nil)
		// Inject user UUID into context
		ctx := context.WithValue(req.Context(), middlewares.UserUUIDKey, "test-uuid")
		req = req.WithContext(ctx)

		controller.GetMe(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *user, response.Data)
		assert.Equal(t, domain.RoleUser, response.Data.Role)
		serviceMock.AssertCalled(t, "GetByUUID", "test-uuid")
	})

	t.Run("unauthorized - missing context key", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()

		w, req := getControllerArgs("GET", "/users/me", nil)
		// Context without UUID

		controller.GetMe(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertNotCalled(t, "GetByUUID")
	})

	t.Run("not found", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("GetByUUID", "test-uuid").Return(nil,
			domain.NewNotFoundError(
				"user.notFound",
			),
		)

		w, req := getControllerArgs("GET", "/users/me", nil)
		ctx := context.WithValue(req.Context(), middlewares.UserUUIDKey, "test-uuid")
		req = req.WithContext(ctx)

		controller.GetMe(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertCalled(t, "GetByUUID", "test-uuid")
	})
}

func TestUsersController_GetUserByUUID(t *testing.T) {
	uuid := "test-uuid"
	user := &domain.User{
		UUID:  "test-uuid",
		Name:  "John Doe",
		Email: "john.doe@example.com",
		Role:  domain.RoleUser,
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()

		serviceMock.On("GetByUUID", mock.Anything).Return(user, nil)

		w, req := getControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *user, response.Data)
		assert.Equal(t, domain.RoleUser, response.Data.Role)
		serviceMock.AssertCalled(t, "GetByUUID", uuid)
	})

	t.Run("not found", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()

		serviceMock.On("GetByUUID", mock.Anything).Return(
			nil,
			domain.NewNotFoundError("user.notFound"),
		)

		w, req := getControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertCalled(t, "GetByUUID", uuid)
	})
}

func TestUsersController_UpdateUser(t *testing.T) {
	uuid := "test-uuid"
	name := "John Updated"
	dto := domain.UserUpdateDTO{Name: &name}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Update", uuid, dto).Return(nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserUpdate &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == uuid &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, dto)
		auditMock.AssertExpectations(t)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := getControllerArgs("PUT", "/users/", struct {
			Test string
		}{Test: "test"})
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Update")
		auditMock.AssertNotCalled(t, "Log")
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Update", uuid, dto).Return(assert.AnError)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserUpdate &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

		w, req := getControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, dto)
		auditMock.AssertExpectations(t)
	})
}

func TestUsersController_DeleteUser(t *testing.T) {
	uuid := "test-uuid"

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Delete", "test-uuid").Return(nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserDelete &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == uuid &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getControllerArgs("DELETE", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")
		auditMock.AssertExpectations(t)
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Delete", "test-uuid").Return(assert.AnError)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserDelete &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

		w, req := getControllerArgs("DELETE", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")
		auditMock.AssertExpectations(t)
	})
}
