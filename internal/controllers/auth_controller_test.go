package controllers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/shared"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const allowedRedirectURI = "http://localhost:3000/callback"

func newTestAuthController() (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.AuditServiceMock) {
	return newTestAuthControllerWithAllowList([]string{allowedRedirectURI})
}

func newTestAuthControllerWithAllowList(allowList []string) (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.AuditServiceMock) {
	return newTestAuthControllerWithOptions(true, allowList)
}

func newTestAuthControllerWithOptions(isSecure bool, allowList []string) (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.AuditServiceMock) {
	controller, authServiceMock, auditMock, _ := newTestAuthControllerWithMiddleware(isSecure, allowList)
	return controller, authServiceMock, auditMock
}

func newTestAuthControllerWithMiddleware(isSecure bool, allowList []string) (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock) {
	authServiceMock := new(mocks.AuthServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	authMiddleware := new(mocks.AuthMiddlewareMock)

	controller := controllers.NewAuthController(authServiceMock, auditMock, authMiddleware, isSecure, allowList)
	return controller, authServiceMock, auditMock, authMiddleware
}

func withSession(req *http.Request, userUUID string, sessionUUID string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{
		UserUUID:    userUUID,
		SessionUUID: sessionUUID,
	}))
}

type oauthFlowCookieNames struct {
	nonce    string
	verifier string
	path     string
}

var oauthFlowCookieModes = []struct {
	name     string
	isSecure bool
	cookies  oauthFlowCookieNames
}{
	{"secure", true, oauthFlowCookieNames{"__Host-oauth_nonce", "__Host-oauth_code_verifier", "/"}},
	{"development", false, oauthFlowCookieNames{"oauth_nonce", "oauth_code_verifier", "/auth/google/callback"}},
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestAuthController_RegisterRoutes(t *testing.T) {
	t.Run("should register routes", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, _, authMiddleware := newTestAuthControllerWithMiddleware(true, []string{allowedRedirectURI})
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Once()

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 1)

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
		controller, serviceMock, auditMock := newTestAuthController()
		serviceMock.On("CredentialsLogin", *dto).Return(domain.AuthTokens{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
		}, nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionLogin &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

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
		assert.Equal(t, "/", accessTokenCookie.Path)
		assert.Equal(t, "/auth/refresh", refreshTokenCookie.Path)
		assert.Equal(t, int(domain.TokenExpirationAccess.Seconds()), accessTokenCookie.MaxAge)
		assert.Equal(t, int(domain.TokenExpirationRefresh.Seconds()), refreshTokenCookie.MaxAge)
		serviceMock.AssertExpectations(t)
		auditMock.AssertExpectations(t)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, _, auditMock := newTestAuthController()
		w, req := getControllerArgs("POST", "/auth/login", map[string]string{
			"invalid_field": "value",
		})

		controller.Login(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, response.Message)
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, response.Data)
		auditMock.AssertNotCalled(t, "Log")
	})

	t.Run("unauthorized", func(t *testing.T) {
		controller, serviceMock, auditMock := newTestAuthController()
		serviceMock.On("CredentialsLogin", *dto).Return(domain.AuthTokens{}, domain.NewUnauthorizedError("auth.invalidCredentials"))
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionLogin &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

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
		auditMock.AssertExpectations(t)
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
		assert.Equal(t, "/", accessTokenCookie.Path)
		assert.Equal(t, "/auth/refresh", refreshTokenCookie.Path)
		assert.Equal(t, int(domain.TokenExpirationAccess.Seconds()), accessTokenCookie.MaxAge)
		assert.Equal(t, int(domain.TokenExpirationRefresh.Seconds()), refreshTokenCookie.MaxAge)
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
	const (
		userUUID    = "user-uuid"
		sessionUUID = "session-uuid"
	)

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock := newTestAuthController()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionLogout &&
				d.Status == domain.AuditStatusSuccess &&
				d.ActorUUID != nil && *d.ActorUUID == userUUID
		})).Return(nil)

		serviceMock.On("Logout", userUUID, sessionUUID).Return(nil).Once()

		w, req := getControllerArgs("POST", "/auth/logout", nil)
		req = withSession(req, userUUID, sessionUUID)

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
		assert.Equal(t, "/", accessTokenCookie.Path)
		assert.Equal(t, "/auth/refresh", refreshTokenCookie.Path)
		assert.Negative(t, accessTokenCookie.MaxAge)
		assert.Negative(t, refreshTokenCookie.MaxAge)
		auditMock.AssertExpectations(t)
		serviceMock.AssertExpectations(t)
	})

	t.Run("error - service error still clears cookies", func(t *testing.T) {
		controller, serviceMock, auditMock := newTestAuthController()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionLogout &&
				d.Status == domain.AuditStatusFailure
		})).Return(nil)
		serviceMock.On("Logout", userUUID, sessionUUID).
			Return(domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))).Once()

		w, req := getControllerArgs("POST", "/auth/logout", nil)
		req = withSession(req, userUUID, sessionUUID)

		controller.Logout(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		for _, cookie := range w.Result().Cookies() {
			assert.Empty(t, cookie.Value)
			assert.Negative(t, cookie.MaxAge)
		}
		assert.Len(t, w.Result().Cookies(), 2)
		auditMock.AssertExpectations(t)
	})
}

func TestAuthController_LoginWithOAuthProvider(t *testing.T) {
	for _, mode := range oauthFlowCookieModes {
		t.Run("success - "+mode.name, func(t *testing.T) {
			controller, serviceMock, _ := newTestAuthControllerWithOptions(mode.isSecure, []string{allowedRedirectURI})
			provider := domain.OAuthProviderGoogle
			authURL := "https://accounts.google.com/o/oauth2/v2/auth?state=valid-state"

			serviceMock.On("StartOAuthLogin", domain.StartOAuthLoginDTO{
				Provider:    provider,
				RedirectURI: allowedRedirectURI,
			}).Return(&domain.StartOAuthLoginResult{
				AuthURL:      authURL,
				Nonce:        "nonce-123",
				CodeVerifier: "verifier-123",
			}, nil).Once()

			w, req := getControllerArgs("GET", "/auth/google/login?redirect_uri="+allowedRedirectURI, nil)
			req.SetPathValue("provider", string(provider))

			controller.LoginWithOAuthProvider(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, authURL, w.Header().Get("Location"))

			cookies := w.Result().Cookies()
			for name, value := range map[string]string{
				mode.cookies.nonce:    "nonce-123",
				mode.cookies.verifier: "verifier-123",
			} {
				cookie := findCookie(cookies, name)
				require.NotNil(t, cookie, name)
				assert.Equal(t, value, cookie.Value)
				assert.Equal(t, mode.cookies.path, cookie.Path)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, mode.isSecure, cookie.Secure)
				assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
				assert.Equal(t, int(domain.TokenExpirationOAuthState.Seconds()), cookie.MaxAge)
			}
			serviceMock.AssertExpectations(t)
		})
	}

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

	t.Run("bad request - redirect_uri validation", func(t *testing.T) {
		cases := []struct {
			name      string
			allowList []string
			query     string
		}{
			{"not in allow list", []string{allowedRedirectURI}, "?redirect_uri=https://evil.example/callback"},
			{"prefix of allowed uri", []string{allowedRedirectURI}, "?redirect_uri=http://localhost:3000/callback/extra"},
			{"missing redirect_uri", []string{allowedRedirectURI}, ""},
			{"empty redirect_uri", []string{allowedRedirectURI}, "?redirect_uri="},
			{"empty allow list", []string{}, "?redirect_uri=" + allowedRedirectURI},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				controller, serviceMock, _ := newTestAuthControllerWithAllowList(tc.allowList)

				w, req := getControllerArgs("GET", "/auth/google/login"+tc.query, nil)
				req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

				controller.LoginWithOAuthProvider(w, req)

				var response api.ResponseBody[any]
				err := json.Unmarshal(w.Body.Bytes(), &response)

				assert.Nil(t, err)
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.NotEmpty(t, response.Error)
				assert.Empty(t, w.Header().Get("Location"))
				assert.Empty(t, w.Result().Cookies())
				serviceMock.AssertNotCalled(t, "StartOAuthLogin", mock.Anything)
			})
		}
	})

	t.Run("internal server error - StartOAuthLogin fails", func(t *testing.T) {
		controller, serviceMock, _ := newTestAuthController()
		provider := domain.OAuthProviderGoogle

		serviceMock.On("StartOAuthLogin", domain.StartOAuthLoginDTO{
			Provider:    provider,
			RedirectURI: allowedRedirectURI,
		}).Return(nil, errors.New("provider not configured")).Once()

		w, req := getControllerArgs("GET", "/auth/google/login?redirect_uri="+allowedRedirectURI, nil)
		req.SetPathValue("provider", string(provider))

		controller.LoginWithOAuthProvider(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		assert.Empty(t, w.Result().Cookies())
		serviceMock.AssertExpectations(t)
	})
}

func assertOAuthFlowCookiesCleared(t *testing.T, cookies []*http.Cookie, names oauthFlowCookieNames) {
	t.Helper()

	for _, name := range []string{names.nonce, names.verifier} {
		cookie := findCookie(cookies, name)
		require.NotNil(t, cookie, name)
		assert.Empty(t, cookie.Value)
		assert.Equal(t, names.path, cookie.Path)
		assert.Negative(t, cookie.MaxAge)
	}
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
		assert.Empty(t, w.Result().Cookies())
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
	})

	for _, mode := range oauthFlowCookieModes {
		t.Run("success - "+mode.name, func(t *testing.T) {
			controller, authServiceMock, auditMock := newTestAuthControllerWithOptions(mode.isSecure, []string{allowedRedirectURI})
			provider := domain.OAuthProviderGoogle
			state := "valid-state"
			code := "auth-code"
			redirectURI := "http://localhost:3000/callback"
			userUUID := "user-uuid"

			dto := domain.OAuthLoginDTO{
				Provider:     provider,
				State:        state,
				Code:         code,
				Nonce:        "nonce-123",
				CodeVerifier: "verifier-123",
			}

			result := &domain.OAuthLoginResult{
				User: &domain.User{UUID: userUUID, Email: "test@example.com", Name: "Test User"},
				Tokens: domain.AuthTokens{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
				},
				RedirectURI: redirectURI,
			}

			authServiceMock.On("OAuthLogin", dto).Return(result, nil).Once()

			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionOAuthLogin &&
					d.Status == domain.AuditStatusSuccess &&
					d.ResourceUUID == userUUID
			})).Return(nil).Once()

			w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
			req.SetPathValue("provider", string(provider))
			req.AddCookie(&http.Cookie{Name: mode.cookies.nonce, Value: "nonce-123"})
			req.AddCookie(&http.Cookie{Name: mode.cookies.verifier, Value: "verifier-123"})

			controller.OAuthProviderCallback(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, redirectURI, w.Header().Get("Location"))

			cookies := w.Result().Cookies()
			assert.NotNil(t, findCookie(cookies, "access_token"))
			assert.NotNil(t, findCookie(cookies, "refresh_token"))
			assertOAuthFlowCookiesCleared(t, cookies, mode.cookies)

			authServiceMock.AssertExpectations(t)
			auditMock.AssertExpectations(t)
		})
	}

	t.Run("forwards empty values when flow cookies are missing", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		dto := domain.OAuthLoginDTO{
			Provider: domain.OAuthProviderGoogle,
			State:    "valid-state",
			Code:     "auth-code",
		}
		authServiceMock.On("OAuthLogin", dto).Return(nil, domain.NewUnauthorizedError("auth.oauthLogin.nonceMismatch")).Once()
		auditMock.On("Log", mock.Anything).Return(nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state=valid-state&code=auth-code", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, w.Result().Cookies())
		authServiceMock.AssertExpectations(t)
	})

	t.Run("provider error - redirects to verified redirect_uri and clears flow cookies", func(t *testing.T) {
		for _, mode := range oauthFlowCookieModes {
			t.Run(mode.name, func(t *testing.T) {
				controller, authServiceMock, auditMock := newTestAuthControllerWithOptions(mode.isSecure, []string{allowedRedirectURI})
				authServiceMock.On("VerifyOAuthState", domain.VerifyOAuthStateDTO{
					Provider: domain.OAuthProviderGoogle,
					State:    "valid-state",
					Nonce:    "nonce-123",
				}).Return(allowedRedirectURI, nil).Once()
				auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
					return d.Action == domain.AuditActionOAuthLogin &&
						d.Status == domain.AuditStatusFailure &&
						d.FailureReason != nil && *d.FailureReason == "access_denied"
				})).Return(nil).Once()

				w, req := getControllerArgs("GET", "/auth/google/callback?state=valid-state&error=access_denied&error_description=user+said+no", nil)
				req.SetPathValue("provider", string(domain.OAuthProviderGoogle))
				req.AddCookie(&http.Cookie{Name: mode.cookies.nonce, Value: "nonce-123"})

				controller.OAuthProviderCallback(w, req)

				assert.Equal(t, http.StatusFound, w.Code)
				assert.Equal(t, allowedRedirectURI+"?error=access_denied", w.Header().Get("Location"))
				cookies := w.Result().Cookies()
				assertOAuthFlowCookiesCleared(t, cookies, mode.cookies)
				assert.Nil(t, findCookie(cookies, "access_token"))
				authServiceMock.AssertNotCalled(t, "OAuthLogin", mock.Anything)
				authServiceMock.AssertExpectations(t)
				auditMock.AssertExpectations(t)
			})
		}
	})

	t.Run("provider error - unknown error code maps to access_denied", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		authServiceMock.On("VerifyOAuthState", mock.Anything).Return(allowedRedirectURI, nil).Once()
		auditMock.On("Log", mock.Anything).Return(nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state=valid-state&error=%3Cscript%3E", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, allowedRedirectURI+"?error=access_denied", w.Header().Get("Location"))
	})

	t.Run("provider error - known error code is forwarded", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		authServiceMock.On("VerifyOAuthState", mock.Anything).Return(allowedRedirectURI, nil).Once()
		auditMock.On("Log", mock.Anything).Return(nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state=valid-state&error=server_error", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, allowedRedirectURI+"?error=server_error", w.Header().Get("Location"))
	})

	t.Run("provider error - state verification failure does not redirect or clear cookies", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		authServiceMock.On("VerifyOAuthState", mock.Anything).Return("", domain.NewUnauthorizedError("auth.oauthLogin.nonceMismatch")).Once()
		auditMock.On("Log", mock.Anything).Return(nil).Maybe()

		w, req := getControllerArgs("GET", "/auth/google/callback?state=forged&error=access_denied", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, w.Header().Get("Location"))
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("provider error - redirect_uri outside allow-list is not followed", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		authServiceMock.On("VerifyOAuthState", mock.Anything).Return("https://evil.test/cb", nil).Once()
		auditMock.On("Log", mock.Anything).Return(nil).Maybe()

		w, req := getControllerArgs("GET", "/auth/google/callback?state=valid-state&error=access_denied", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, w.Header().Get("Location"))
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("provider error - missing state", func(t *testing.T) {
		controller, authServiceMock, _ := newTestAuthController()

		w, req := getControllerArgs("GET", "/auth/google/callback?error=access_denied", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGoogle))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, w.Result().Cookies())
		authServiceMock.AssertNotCalled(t, "VerifyOAuthState", mock.Anything)
	})

	t.Run("error - service returns error", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		provider := domain.OAuthProviderGoogle
		state := "valid-state"
		code := "auth-code"

		dto := domain.OAuthLoginDTO{
			Provider: provider,
			State:    state,
			Code:     code,
		}

		authServiceMock.On("OAuthLogin", dto).Return(nil, domain.NewUnauthorizedError("auth.invalidToken")).Once()

		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionOAuthLogin &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil).Once()

		w, req := getControllerArgs("GET", "/auth/google/callback?state="+state+"&code="+code, nil)
		req.SetPathValue("provider", string(provider))

		controller.OAuthProviderCallback(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Empty(t, w.Result().Cookies())
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		authServiceMock.AssertExpectations(t)
		auditMock.AssertExpectations(t)
	})
}
