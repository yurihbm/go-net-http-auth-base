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

func TestAuthController_RegisterRoutes(t *testing.T) {
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

func TestAuthController_Login(t *testing.T) {
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
		assert.Contains(t, response.Message, "auth.login.badRequest")
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
	})

	t.Run("unauthorized", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		serviceMock.On("CredentialsLogin", *dto).Return(domain.AuthTokens{}, domain.NewUnauthorizedError("auth.invalidCredentials"))
		w, req := getControllerArgs("POST", "/auth/login", dto)

		controller.Login(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		// Status code will be based on CredentialsLogin returned error type
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
	})
}

func TestAuthController_RefreshToken(t *testing.T) {
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
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
	})

	t.Run("unauthorized - invalid token", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		refreshTokenValue := "invalid-token"
		dto := domain.RefreshTokenDTO{
			RefreshToken: refreshTokenValue,
		}
		serviceMock.On("RefreshToken", dto).Return(
			domain.AuthTokens{},
			domain.NewUnauthorizedError("auth.invalidRefreshToken"),
		)
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
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
		assert.Empty(t, response.Message)
		serviceMock.AssertExpectations(t)
	})
}

func TestAuthController_Logout(t *testing.T) {
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

func TestAuthController_LoginWithOAuthProvider(t *testing.T) {
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
		assert.Empty(t, response.Data)
		assert.Empty(t, response.Message)
		assert.NotEmpty(t, response.Error)
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
		assert.Empty(t, response.Data)
		assert.Empty(t, response.Message)
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

		serviceMock.On("GetOAuthProviderAuthURL", provider, stateToken).Return(
			"", errors.New("provider not configured"),
		).Once()

		w, req := getControllerArgs("GET", "/auth/google/login?redirect_uri="+redirectURI, nil)
		req.SetPathValue("provider", string(provider))

		controller.LoginWithOAuthProvider(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertExpectations(t)
	})
}

func TestAuthController_OAuthProviderCallback(t *testing.T) {
	t.Run("bad request - invalid provider", func(t *testing.T) {
		controller, _, _ := newTestAuthController()
		w, req := getControllerArgs("GET", "/auth/invalid/callback?state=state&code=code", nil)
		req.SetPathValue("provider", "invalid")

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
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
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
	})

	t.Run("unauthorized - invalid state token", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "invalid-state"
		code := "auth-code"

		serviceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(nil, domain.NewUnauthorizedError("auth.invalidToken")).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
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
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
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
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
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
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		authServiceMock.AssertExpectations(t)
	})

	t.Run("success - existing linked user", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "user-uuid"
		providerUserID := "provider-user-id"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  "Test User",
			Email: "test@example.com",
		}

		userOAuthProvider := &domain.UserOAuthProvider{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  "test@example.com",
		}

		user := &domain.User{
			UUID:  userUUID,
			Email: "test@example.com",
			Name:  "Test User",
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(userOAuthProvider, nil).Once()

		usersServiceMock.On("GetByUUID", userUUID).Return(user, nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceAccess
		})).Return("access-token", nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceRefresh
		})).Return("refresh-token", nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, redirectURI, w.Header().Get("Location"))

		cookies := w.Result().Cookies()
		var hasAccess, hasRefresh bool
		for _, c := range cookies {
			if c.Name == "access_token" {
				hasAccess = true
			}
			if c.Name == "refresh_token" {
				hasRefresh = true
			}
		}
		assert.True(t, hasAccess)
		assert.True(t, hasRefresh)

		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("success - link to existing user", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "user-uuid"
		providerUserID := "provider-user-id"
		email := "test@example.com"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  "Test User",
			Email: email,
		}

		user := &domain.User{
			UUID:  userUUID,
			Email: email,
			Name:  "Test User",
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("GetByEmail", email).Return(user, nil).Once()

		authServiceMock.On("AddUserOAuthProvider", domain.AddUserOAuthProviderDTO{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  email,
		}).Return(nil, nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceAccess
		})).Return("access-token", nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceRefresh
		})).Return("refresh-token", nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, redirectURI, w.Header().Get("Location"))
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("success - create new user", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "new-user-uuid"
		providerUserID := "provider-user-id"
		email := "new@example.com"
		name := "New User"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  name,
			Email: email,
		}

		newUser := &domain.User{
			UUID:  userUUID,
			Email: email,
			Name:  name,
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On(
			"GetOAuthProviderUserInfo",
			mock.MatchedBy(func(ctx any) bool { return true }), provider, code,
		).Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("GetByEmail", email).Return(
			nil,
			domain.NewNotFoundError("not found"),
		).Once()

		usersServiceMock.On("Create", domain.CreateUserDTO{
			Name:     name,
			Email:    email,
			Password: "",
		}).Return(newUser, nil).Once()

		authServiceMock.On("AddUserOAuthProvider", domain.AddUserOAuthProviderDTO{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  email,
		}).Return(nil, nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceAccess
		})).Return("access-token", nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceRefresh
		})).Return("refresh-token", nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, redirectURI, w.Header().Get("Location"))
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("internal server error - failed to fetch user (Case 1)", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "user-uuid"
		providerUserID := "provider-user-id"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  "Test User",
			Email: "test@example.com",
		}

		userOAuthProvider := &domain.UserOAuthProvider{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  "test@example.com",
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(userOAuthProvider, nil).Once()

		usersServiceMock.On("GetByUUID", userUUID).Return(nil, errors.New("db error")).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("internal server error - failed to link provider (Case 2)", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "user-uuid"
		providerUserID := "provider-user-id"
		email := "test@example.com"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  "Test User",
			Email: email,
		}

		user := &domain.User{
			UUID:  userUUID,
			Email: email,
			Name:  "Test User",
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("GetByEmail", email).Return(user, nil).Once()

		authServiceMock.On("AddUserOAuthProvider", domain.AddUserOAuthProviderDTO{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  email,
		}).Return(nil, errors.New("db error")).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("internal server error - failed to create user (Case 3)", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		providerUserID := "provider-user-id"
		email := "new@example.com"
		name := "New User"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  name,
			Email: email,
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("Create", domain.CreateUserDTO{
			Name:     name,
			Email:    email,
			Password: "",
		}).Return(nil, errors.New("db error")).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("internal server error - failed to link provider during creation (Case 3 - Rollback)", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "new-user-uuid"
		providerUserID := "provider-user-id"
		email := "new@example.com"
		name := "New User"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  name,
			Email: email,
		}

		newUser := &domain.User{
			UUID:  userUUID,
			Email: email,
			Name:  name,
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo", mock.MatchedBy(func(ctx any) bool { return true }), provider, code).
			Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("GetByEmail", email).Return(nil, domain.NewNotFoundError("not found")).Once()

		usersServiceMock.On("Create", domain.CreateUserDTO{
			Name:     name,
			Email:    email,
			Password: "",
		}).Return(newUser, nil).Once()

		authServiceMock.On("AddUserOAuthProvider", domain.AddUserOAuthProviderDTO{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  email,
		}).Return(nil, errors.New("db error")).Once()

		usersServiceMock.On("Delete", userUUID).Return(nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})

	t.Run("internal server error - token generation fails", func(t *testing.T) {
		controller, authServiceMock, usersServiceMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"
		redirectURI := "http://localhost:3000/callback"
		userUUID := "user-uuid"
		providerUserID := "provider-user-id"

		verifiedTokenData := &domain.VerifiedTokenData{
			Subject:    string(provider),
			Audience:   domain.TokenAudienceOAuthState,
			Expiration: time.Now().Add(time.Hour).Unix(),
			Payload: map[string]any{
				"redirect_uri": redirectURI,
			},
		}

		userInfo := &domain.OAuthProviderUserInfo{
			ID:    providerUserID,
			Name:  "Test User",
			Email: "test@example.com",
		}

		userOAuthProvider := &domain.UserOAuthProvider{
			UserUUID:       userUUID,
			Provider:       provider,
			ProviderUserID: providerUserID,
			ProviderEmail:  "test@example.com",
		}

		user := &domain.User{
			UUID:  userUUID,
			Email: "test@example.com",
			Name:  "Test User",
		}

		authServiceMock.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    state,
			Audience: domain.TokenAudienceOAuthState,
		}).Return(verifiedTokenData, nil).Once()

		authServiceMock.On("GetOAuthProviderUserInfo",
			mock.MatchedBy(func(ctx any) bool { return true }),
			provider,
			code,
		).Return(userInfo, nil).Once()

		authServiceMock.On("GetUserOAuthProvider", domain.GetUserOAuthProviderDTO{
			Provider:       provider,
			ProviderUserID: providerUserID,
		}).Return(userOAuthProvider, nil).Once()

		usersServiceMock.On("GetByUUID", userUUID).Return(user, nil).Once()

		authServiceMock.On("GenerateToken", mock.MatchedBy(func(dto domain.GenerateTokenDTO) bool {
			return dto.Subject == userUUID && dto.Audience == domain.TokenAudienceAccess
		})).Return("", errors.New("token error")).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		authServiceMock.AssertExpectations(t)
		usersServiceMock.AssertExpectations(t)
	})
}
