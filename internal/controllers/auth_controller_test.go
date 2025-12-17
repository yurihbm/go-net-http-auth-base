package controllers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestAuthController() (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.UsersServiceMock) {
	authServiceMock := new(mocks.AuthServiceMock)
	usersServiceMock := new(mocks.UsersServiceMock)

	controller := controllers.NewAuthController(authServiceMock, usersServiceMock)
	return controller, authServiceMock, usersServiceMock
}

func TestRegisterRoutes(t *testing.T) {
	t.Run("should register routes", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, _ := newTestAuthController()

		controller.RegisterRoutes(router)

		// Verify routes are registered by checking if requests match
		routes := []struct {
			method string
			path   string
		}{
			{"POST", "/auth/login"},
			{"POST", "/auth/refresh"},
			{"POST", "/auth/logout"},
			{"GET", "/auth/google/login"},
			{"GET", "/auth/google/callback"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			_, pattern := router.Handler(req)
			assert.NotEmpty(t, pattern)
		}
	})
}

func TestLogin(t *testing.T) {
	dto := &domain.CredentialsLoginDTO{
		Email:    "test@mail.com",
		Password: "password123",
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
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
		controller, _, _ := newTestAuthController()
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
		controller, serviceMock, _ := newTestAuthController()
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
		controller, serviceMock, _ := newTestAuthController()
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
		controller, _, _ := newTestAuthController()
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
		controller, serviceMock, _ := newTestAuthController()
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
		controller, _, _ := newTestAuthController()
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

func TestLoginWithOAuthProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		redirectURI := "http://localhost:3000/callback"
		stateToken := "valid-state-token"
		authURL := "https://accounts.google.com/o/oauth2/v2/auth?state=" + stateToken

		serviceMock.On("GenerateToken", domain.GenerateTokenDTO{
			Audience: domain.TokenAudienceOAuthState,
			Subject:  string(provider),
			Payload: map[string]string{
				"redirect_uri": redirectURI,
			},
		}).Return(stateToken, nil).Once()

		serviceMock.On("GetOAuthProviderAuthURL", provider, stateToken).Return(authURL, nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/login?redirect_uri="+redirectURI, nil)
		req.SetPathValue("provider", string(provider))

		controller.LoginWithOAuthProvider(w, req)

		// Should redirect to OAuth provider
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, authURL, w.Header().Get("Location"))
		serviceMock.AssertExpectations(t)
	})

	t.Run("bad request - invalid provider", func(t *testing.T) {
		controller, _, _ := newTestAuthController()
		w, req := getControllerArgs("GET", "/auth/invalid-provider/login", nil)
		req.SetPathValue("provider", "invalid-provider")

		controller.LoginWithOAuthProvider(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, response.Message, "auth.provider_login.bad_request")
		assert.Equal(t, response.Error, "invalid OAuth provider")
	})

	t.Run("internal server error - token generation fails", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		redirectURI := "http://localhost:3000/callback"

		serviceMock.On("GenerateToken", domain.GenerateTokenDTO{
			Audience: domain.TokenAudienceOAuthState,
			Subject:  string(provider),
			Payload: map[string]string{
				"redirect_uri": redirectURI,
			},
		}).Return("", errors.New("token generation failed")).Once()

		w, req := getControllerArgs("GET", "/auth/google/login?redirect_uri="+redirectURI, nil)
		req.SetPathValue("provider", string(provider))

		controller.LoginWithOAuthProvider(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, response.Message, "auth.provider_login.failed")
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertExpectations(t)
	})

	t.Run("internal server error - GetOAuthProviderAuthURL fails", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		redirectURI := "http://localhost:3000/callback"
		stateToken := "valid-state-token"

		serviceMock.On("GenerateToken", domain.GenerateTokenDTO{
			Audience: domain.TokenAudienceOAuthState,
			Subject:  string(provider),
			Payload: map[string]string{
				"redirect_uri": redirectURI,
			},
		}).Return(stateToken, nil).Once()

		serviceMock.On("GetOAuthProviderAuthURL", provider, stateToken).Return("", errors.New("provider not configured")).Once()

		w, req := getControllerArgs("GET", "/auth/google/login?redirect_uri="+redirectURI, nil)
		req.SetPathValue("provider", string(provider))

		controller.LoginWithOAuthProvider(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, response.Message, "auth.provider_login.failed")
		assert.Contains(t, response.Error, "provider not configured")
		serviceMock.AssertExpectations(t)
	})
}

func TestOAuthProviderCallback(t *testing.T) {
	t.Run("bad request - invalid provider", func(t *testing.T) {
		controller, _, _ := newTestAuthController()
		w, req := getControllerArgs("GET", "/auth/invalid/callback?state=state&code=code", nil)
		req.SetPathValue("provider", "invalid")

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, response.Message, "auth.provider_callback.bad_request")
		assert.Equal(t, response.Error, "invalid OAuth provider")
	})

	t.Run("bad request - missing state or code", func(t *testing.T) {
		controller, _, _ := newTestAuthController()
		w, req := getControllerArgs("GET", "/auth/google/callback", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, response.Message, "auth.provider_callback.bad_request")
		assert.Contains(t, response.Error, "missing state or code")
	})

	t.Run("unauthorized - invalid state token", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "invalid-state"
		code := "auth-code"

		serviceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(nil, errors.New("invalid token")).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, response.Message, "auth.provider_callback.invalid_state")
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertExpectations(t)
	})

	t.Run("bad request - invalid redirect_uri in state", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload:    map[string]any{
				// Missing redirect_uri
			},
		}

		serviceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, response.Message, "auth.provider_callback.invalid_state")
		assert.Contains(t, response.Error, "invalid redirect_uri")
		serviceMock.AssertExpectations(t)
	})

	t.Run("unauthorized - provider GetUserInfo fails", func(t *testing.T) {
		authServiceMock := new(mocks.AuthServiceMock)
		usersServiceMock := new(mocks.UsersServiceMock)
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(nil, errors.New("provider error")).Once()

		controller := controllers.NewAuthController(authServiceMock, usersServiceMock)

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, response.Message, "auth.provider_callback.token_exchange_failed")
		assert.NotEmpty(t, response.Error)
		authServiceMock.AssertExpectations(t)
	})

	t.Run("internal server error - missing required fields from provider", func(t *testing.T) {
		authServiceMock := new(mocks.AuthServiceMock)
		usersServiceMock := new(mocks.UsersServiceMock)
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    "",
			Name:  "Test User",
			Email: "test@example.com",
		}

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		controller := controllers.NewAuthController(authServiceMock, usersServiceMock)

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, response.Message, "auth.provider_callback.invalid_user_info")
		assert.Contains(t, response.Error, "missing required fields")
		authServiceMock.AssertExpectations(t)
	})
}
