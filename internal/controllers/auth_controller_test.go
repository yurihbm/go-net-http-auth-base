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
)

func newTestAuthController() (*controllers.AuthController, *mocks.AuthServiceMock) {
	serviceMock := new(mocks.AuthServiceMock)
	controller := controllers.NewAuthController(serviceMock)
	return controller, serviceMock
}

func TestLogin(t *testing.T) {
	dto := &domain.CredentialsLoginDTO{
		Email:    "test@mail.com",
		Password: "password123",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock := newTestAuthController()
		serviceMock.On("CredentialsLogin", *dto).Return(domain.AuthTokens{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil)
		w, req := getControllerArgs("POST", "/auth/login", dto)

		controller.Login(w, req)

		var response api.ResponseBody[domain.AuthTokens]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, response.Data.AccessToken, "access-token")
		assert.Equal(t, response.Data.RefreshToken, "refresh-token")
		serviceMock.AssertExpectations(t)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, _ := newTestAuthController()
		w, req := getControllerArgs("POST", "/auth/login", map[string]string{
			"invalid_field": "value",
		})

		controller.Login(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, response.Message, "auth.login.bad_request")
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
	})

	t.Run("unauthorized", func(t *testing.T) {
		controller, serviceMock := newTestAuthController()
		serviceMock.On("CredentialsLogin", *dto).Return(domain.AuthTokens{}, assert.AnError)
		w, req := getControllerArgs("POST", "/auth/login", dto)

		controller.Login(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, response.Message, "auth.login.failed")
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
	})
}

func TestRefreshToken(t *testing.T) {
	dto := &domain.RefreshTokenDTO{
		RefreshToken: "refresh-token",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock := newTestAuthController()
		serviceMock.On("RefreshToken", *dto).Return(domain.AuthTokens{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		}, nil)
		w, req := getControllerArgs("POST", "/auth/refresh", dto)

		controller.RefreshToken(w, req)

		var response api.ResponseBody[domain.AuthTokens]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, response.Data.AccessToken, "new-access-token")
		assert.Equal(t, response.Data.RefreshToken, "new-refresh-token")
		serviceMock.AssertExpectations(t)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, _ := newTestAuthController()
		w, req := getControllerArgs("POST", "/auth/refresh", map[string]string{
			"invalid_field": "value",
		})

		controller.RefreshToken(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, response.Message, "auth.refresh.bad_request")
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
	})

	t.Run("unauthorized", func(t *testing.T) {
		controller, serviceMock := newTestAuthController()
		serviceMock.On("RefreshToken", *dto).Return(domain.AuthTokens{}, assert.AnError)
		w, req := getControllerArgs("POST", "/auth/refresh", dto)

		controller.RefreshToken(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, response.Message, "auth.refresh.failed")
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
		serviceMock.AssertExpectations(t)
	})
}
