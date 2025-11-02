package controllers_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

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

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, response.Message, "auth.login.success")

		// Verify that access_token and refresh_token cookies are set
		cookies := w.Result().Cookies()
		var accessTokenCookie, refreshTokenCookie *http.Cookie
		for _, cookie := range cookies {
			switch cookie.Name {
			case "access_token":
				accessTokenCookie = cookie
			case "refresh_token":
				refreshTokenCookie = cookie
			}
		}

		assert.NotNil(t, accessTokenCookie)
		assert.NotNil(t, refreshTokenCookie)
		assert.Equal(t, accessTokenCookie.Value, "access-token")
		assert.Equal(t, refreshTokenCookie.Value, "refresh-token")
		assert.True(t, accessTokenCookie.HttpOnly)
		assert.True(t, refreshTokenCookie.HttpOnly)
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
	t.Run("success", func(t *testing.T) {
		controller, serviceMock := newTestAuthController()
		refreshTokenValue := "refresh-token"
		dto := domain.RefreshTokenDTO{
			RefreshToken: refreshTokenValue,
		}
		serviceMock.On("RefreshToken", dto).Return(domain.AuthTokens{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		}, nil)

		w, req := getControllerArgs("POST", "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: refreshTokenValue,
		})

		controller.RefreshToken(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, response.Message, "auth.refresh.success")

		// Verify that new tokens are set as cookies
		cookies := w.Result().Cookies()
		var accessTokenCookie, refreshTokenCookie *http.Cookie
		for _, cookie := range cookies {
			switch cookie.Name {
			case "access_token":
				accessTokenCookie = cookie
			case "refresh_token":
				refreshTokenCookie = cookie
			}
		}

		assert.NotNil(t, accessTokenCookie)
		assert.NotNil(t, refreshTokenCookie)
		assert.Equal(t, accessTokenCookie.Value, "new-access-token")
		assert.Equal(t, refreshTokenCookie.Value, "new-refresh-token")
		assert.True(t, accessTokenCookie.HttpOnly)
		assert.True(t, refreshTokenCookie.HttpOnly)
		serviceMock.AssertExpectations(t)
	})

	t.Run("bad request - missing refresh token cookie", func(t *testing.T) {
		controller, _ := newTestAuthController()
		w, req := getControllerArgs("POST", "/auth/refresh", nil)
		// No cookie set

		controller.RefreshToken(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, response.Message, "auth.refresh.bad_request")
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
	})

	t.Run("unauthorized - invalid token", func(t *testing.T) {
		controller, serviceMock := newTestAuthController()
		refreshTokenValue := "invalid-token"
		dto := domain.RefreshTokenDTO{
			RefreshToken: refreshTokenValue,
		}
		serviceMock.On("RefreshToken", dto).Return(domain.AuthTokens{}, assert.AnError)
		w, req := getControllerArgs("POST", "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: refreshTokenValue,
		})

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

func TestLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, _ := newTestAuthController()
		w, req := getControllerArgs("POST", "/auth/logout", nil)

		controller.Logout(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, response.Message, "auth.logout.success")

		// Verify that auth cookies are deleted (set with zero expiration)
		cookies := w.Result().Cookies()
		var accessTokenCookie, refreshTokenCookie *http.Cookie
		for _, cookie := range cookies {
			switch cookie.Name {
			case "access_token":
				accessTokenCookie = cookie
			case "refresh_token":
				refreshTokenCookie = cookie
			}
		}

		assert.NotNil(t, accessTokenCookie)
		assert.NotNil(t, refreshTokenCookie)
		assert.Empty(t, accessTokenCookie.Value)
		assert.Empty(t, refreshTokenCookie.Value)
		assert.True(t, accessTokenCookie.HttpOnly)
		assert.True(t, refreshTokenCookie.HttpOnly)
		// Check that cookies are expired (set to past time)
		assert.True(t, accessTokenCookie.Expires.Before(time.Now()))
		assert.True(t, refreshTokenCookie.Expires.Before(time.Now()))
	})
}
