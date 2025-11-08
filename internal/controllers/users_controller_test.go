package controllers_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestUsersController() (*controllers.UsersController, *mocks.UsersServiceMock, *mocks.AuthMiddlewareMock) {
	serviceMock := new(mocks.UsersServiceMock)
	middlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.NewUsersController(serviceMock, middlewareMock)

	return controller, serviceMock, middlewareMock
}

func TestUsersControllerRegisterRoutes(t *testing.T) {
	t.Run("should register routes with auth middleware", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, authMiddleware := newTestUsersController()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(4)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 4)
	})
}

func TestCreateUser(t *testing.T) {
	user := &domain.User{
		UUID:  "test-uuid",
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}
	dto := domain.CreateUserDTO{
		Name:     "John Doe",
		Email:    "john.doe@example.com",
		Password: "password123",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("Create", dto).Return(user, nil)
		w, req := getControllerArgs(
			"POST",
			"/users/",
			dto,
		)

		controller.CreateUser(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, response.Data, *user)
		serviceMock.AssertCalled(t, "Create", dto)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

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
		assert.Contains(t, response.Message, "user.create.invalid_password")
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertNotCalled(t, "Create")
	})

	t.Run("short password", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

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

	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("Create", dto).Return(nil, assert.AnError)

		w, req := getControllerArgs(
			"POST",
			"/users/",
			dto,
		)

		controller.CreateUser(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Create", dto)
	})

}

func TestGetUserByUUID(t *testing.T) {
	uuid := "test-uuid"
	user := &domain.User{
		UUID:  "test-uuid",
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("GetByUUID", mock.Anything).Return(user, nil)

		w, req := getControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *user, response.Data)
		serviceMock.AssertCalled(t, "GetByUUID", uuid)
	})

	t.Run("not found", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("GetByUUID", mock.Anything).Return(nil, assert.AnError)

		w, req := getControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
		serviceMock.AssertCalled(t, "GetByUUID", uuid)

	})
}

func TestUpdateUser(t *testing.T) {
	uuid := "test-uuid"
	name := "John Updated"
	dto := domain.UserUpdateDTO{Name: &name}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("Update", uuid, dto).Return(nil)

		w, req := getControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, dto)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		w, req := getControllerArgs("PUT", "/users/", struct {
			Test string
		}{Test: "test"})
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Update")
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("Update", uuid, dto).Return(assert.AnError)

		w, req := getControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, dto)
	})

}

func TestDeleteUser(t *testing.T) {
	uuid := "test-uuid"

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("Delete", "test-uuid").Return(nil)

		w, req := getControllerArgs("DELETE", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, _ := newTestUsersController()

		serviceMock.On("Delete", "test-uuid").Return(assert.AnError)

		w, req := getControllerArgs("DELETE", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")

	})
}
