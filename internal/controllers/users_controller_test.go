package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func getControllerArgs(method string, endpoint string, body any) (*httptest.ResponseRecorder, *http.Request) {
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, endpoint, bytes.NewBuffer(buf))
	w := httptest.NewRecorder()

	return w, req
}

func TestCreateUser(t *testing.T) {
	user := &domain.User{
		UUID:  "test-uuid",
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}
	dto := domain.CreateUserDTO{
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}

	t.Run("success", func(t *testing.T) {
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)

		serviceMock.On("Create", &dto).Return(user, nil)
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
		serviceMock.AssertCalled(t, "Create", &dto)
	})

	t.Run("bad request", func(t *testing.T) {
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)

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
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
		serviceMock.On("Create", &dto).Return(nil, assert.AnError)

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
		serviceMock.AssertCalled(t, "Create", &dto)
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
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
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
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
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
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
		serviceMock.On("Update", uuid, &dto).Return(nil)

		w, req := getControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, &dto)
	})

	t.Run("bad request", func(t *testing.T) {
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)

		w, req := getControllerArgs("PUT", "/users/", struct {
			Test string
		}{Test: "test"})
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Update")
	})

	t.Run("service error", func(t *testing.T) {
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
		serviceMock.On("Update", uuid, &dto).Return(assert.AnError)

		w, req := getControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Update", uuid, &dto)
	})

}

func TestDeleteUser(t *testing.T) {
	uuid := "test-uuid"

	t.Run("success", func(t *testing.T) {
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
		serviceMock.On("Delete", "test-uuid").Return(nil)

		w, req := getControllerArgs("DELETE", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")
	})

	t.Run("service error", func(t *testing.T) {
		serviceMock := new(mocks.UsersServiceMock)
		controller := controllers.NewUsersController(serviceMock)
		serviceMock.On("Delete", "test-uuid").Return(assert.AnError)

		w, req := getControllerArgs("DELETE", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Delete", "test-uuid")

	})
}
