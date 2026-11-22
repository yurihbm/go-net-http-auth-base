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

	controller := controllers.NewAuthController(authServiceMock, new(mocks.StepUpServiceMock), new(mocks.PendingSignupServiceMock), auditMock, authMiddleware, isSecure, allowList)
	return controller, authServiceMock, auditMock, authMiddleware
}

func newTestAuthControllerWithStepUp() (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.StepUpServiceMock, *mocks.AuditServiceMock) {
	authServiceMock := new(mocks.AuthServiceMock)
	stepUpMock := new(mocks.StepUpServiceMock)
	auditMock := new(mocks.AuditServiceMock)

	controller := controllers.NewAuthController(authServiceMock, stepUpMock, new(mocks.PendingSignupServiceMock), auditMock, new(mocks.AuthMiddlewareMock), true, []string{allowedRedirectURI})
	return controller, authServiceMock, stepUpMock, auditMock
}

func newTestAuthControllerWithSignup(isSecure bool) (*controllers.AuthController, *mocks.AuthServiceMock, *mocks.PendingSignupServiceMock, *mocks.AuditServiceMock) {
	authServiceMock := new(mocks.AuthServiceMock)
	pendingMock := new(mocks.PendingSignupServiceMock)
	auditMock := new(mocks.AuditServiceMock)

	controller := controllers.NewAuthController(authServiceMock, new(mocks.StepUpServiceMock), pendingMock, auditMock, new(mocks.AuthMiddlewareMock), isSecure, []string{allowedRedirectURI})
	return controller, authServiceMock, pendingMock, auditMock
}

func withPendingSignupCookie(req *http.Request, isSecure bool, value string) *http.Request {
	req.AddCookie(&http.Cookie{Name: api.OAuthFlowCookieName(api.PendingSignupCookieName, isSecure), Value: value})
	return req
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
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(4)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 4)

		// Verify routes are registered by checking if requests match
		routes := []struct {
			method string
			path   string
		}{
			{"POST", "/auth/login"},
			{"POST", "/auth/refresh"},
			{"POST", "/auth/logout"},
			{"POST", "/auth/logout-others"},
			{"POST", "/auth/step-up"},
			{"POST", "/auth/step-up/verify"},
			{"POST", "/auth/signup/verify"},
			{"POST", "/auth/signup/resend"},
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

func TestAuthController_LogoutOthers(t *testing.T) {
	const (
		userUUID    = "user-uuid"
		sessionUUID = "session-uuid"
	)

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock := newTestAuthController()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionLogoutOthers &&
				d.Status == domain.AuditStatusSuccess &&
				d.ActorUUID != nil && *d.ActorUUID == userUUID
		})).Return(nil)
		serviceMock.On("LogoutOthers", userUUID, sessionUUID).Return(nil).Once()

		w, req := getControllerArgs("POST", "/auth/logout-others", nil)
		controller.LogoutOthers(w, withSession(req, userUUID, sessionUUID))

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Result().Cookies())
		serviceMock.AssertExpectations(t)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - service error", func(t *testing.T) {
		controller, serviceMock, auditMock := newTestAuthController()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionLogoutOthers && d.Status == domain.AuditStatusFailure
		})).Return(nil)
		serviceMock.On("LogoutOthers", userUUID, sessionUUID).
			Return(domain.NewInternalServerError("sessions.internalServerError", errors.New("db down"))).Once()

		w, req := getControllerArgs("POST", "/auth/logout-others", nil)
		controller.LogoutOthers(w, withSession(req, userUUID, sessionUUID))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		auditMock.AssertExpectations(t)
	})
}

func TestAuthController_RequestStepUp(t *testing.T) {
	const (
		userUUID    = "user-uuid"
		sessionUUID = "session-uuid"
	)

	t.Run("success", func(t *testing.T) {
		controller, _, stepUpMock, auditMock := newTestAuthControllerWithStepUp()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionStepUpRequest && d.Status == domain.AuditStatusSuccess
		})).Return(nil)
		stepUpMock.On("RequestCode", userUUID, sessionUUID).Return(nil).Once()

		w, req := getControllerArgs("POST", "/auth/step-up", nil)
		controller.RequestStepUp(w, withSession(req, userUUID, sessionUUID))

		var response api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.Equal(t, "auth.stepUp.codeSent", response.Message)
		stepUpMock.AssertExpectations(t)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - cooldown", func(t *testing.T) {
		controller, _, stepUpMock, auditMock := newTestAuthControllerWithStepUp()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionStepUpRequest && d.Status == domain.AuditStatusFailure
		})).Return(nil)
		stepUpMock.On("RequestCode", userUUID, sessionUUID).Return(domain.NewTooManyRequestsError("auth.stepUp.cooldown")).Once()

		w, req := getControllerArgs("POST", "/auth/step-up", nil)
		controller.RequestStepUp(w, withSession(req, userUUID, sessionUUID))

		var response api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "auth.stepUp.cooldown", response.Error)
		auditMock.AssertExpectations(t)
	})
}

func TestAuthController_VerifyStepUp(t *testing.T) {
	const (
		userUUID    = "user-uuid"
		sessionUUID = "session-uuid"
		until       = int64(1700000000)
	)
	dto := domain.CodeDTO{Code: "123456"}

	t.Run("success", func(t *testing.T) {
		controller, _, stepUpMock, auditMock := newTestAuthControllerWithStepUp()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionStepUpVerify && d.Status == domain.AuditStatusSuccess
		})).Return(nil)
		stepUpMock.On("VerifyCode", userUUID, sessionUUID, dto.Code).Return(until, nil).Once()

		w, req := getControllerArgs("POST", "/auth/step-up/verify", dto)
		controller.VerifyStepUp(w, withSession(req, userUUID, sessionUUID))

		var response api.ResponseBody[map[string]int64]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "auth.stepUp.verified", response.Message)
		assert.Equal(t, until, response.Data["step_up_until"])
		auditMock.AssertExpectations(t)
	})

	t.Run("error - validation", func(t *testing.T) {
		controller, _, stepUpMock, _ := newTestAuthControllerWithStepUp()

		w, req := getControllerArgs("POST", "/auth/step-up/verify", domain.CodeDTO{Code: "12"})
		controller.VerifyStepUp(w, withSession(req, userUUID, sessionUUID))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		stepUpMock.AssertNotCalled(t, "VerifyCode", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - invalid code", func(t *testing.T) {
		controller, _, stepUpMock, auditMock := newTestAuthControllerWithStepUp()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionStepUpVerify && d.Status == domain.AuditStatusFailure
		})).Return(nil)
		stepUpMock.On("VerifyCode", userUUID, sessionUUID, dto.Code).Return(int64(0), domain.NewUnauthorizedError("auth.stepUp.invalidCode")).Once()

		w, req := getControllerArgs("POST", "/auth/step-up/verify", dto)
		controller.VerifyStepUp(w, withSession(req, userUUID, sessionUUID))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - session revoked", func(t *testing.T) {
		controller, _, stepUpMock, auditMock := newTestAuthControllerWithStepUp()
		auditMock.On("Log", mock.Anything).Return(nil)
		stepUpMock.On("VerifyCode", userUUID, sessionUUID, dto.Code).
			Return(int64(0), domain.ErrStepUpSessionRevoked).Once()

		w, req := getControllerArgs("POST", "/auth/step-up/verify", dto)
		controller.VerifyStepUp(w, withSession(req, userUUID, sessionUUID))

		var response api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "auth.stepUp.sessionRevoked", response.Error)
		assert.Len(t, w.Result().Cookies(), 2)
		for _, cookie := range w.Result().Cookies() {
			assert.Empty(t, cookie.Value)
			assert.Negative(t, cookie.MaxAge)
		}
	})
}

func TestAuthController_VerifySignup(t *testing.T) {
	dto := domain.CodeDTO{Code: "123456"}
	user := &domain.User{UUID: "user-uuid", Name: "New User", Email: "new@example.com", Role: domain.RoleUser}
	result := &domain.SignupResult{User: user, Tokens: domain.AuthTokens{AccessToken: "access", RefreshToken: "refresh"}}

	for _, mode := range []struct {
		name     string
		isSecure bool
	}{{"secure", true}, {"development", false}} {
		t.Run("success sets the auth cookies and clears the pending cookie - "+mode.name, func(t *testing.T) {
			controller, authMock, _, auditMock := newTestAuthControllerWithSignup(mode.isSecure)
			authMock.On("CompleteSignup", "pending-uuid", "123456").Return(result, nil).Once()
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionUserCreate &&
					d.ResourceType == domain.AuditResourceUser &&
					d.ResourceUUID == user.UUID &&
					d.ActorUUID != nil && *d.ActorUUID == user.UUID &&
					d.Status == domain.AuditStatusSuccess
			})).Return(nil).Once()

			w, req := getControllerArgs("POST", "/auth/signup/verify", dto)
			req = withPendingSignupCookie(req, mode.isSecure, "pending-uuid")

			controller.VerifySignup(w, req)

			var response api.ResponseBody[domain.User]
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, http.StatusCreated, w.Code)
			assert.Equal(t, "auth.signup.success", response.Message)
			assert.Equal(t, *user, response.Data)
			cookies := w.Result().Cookies()
			access := findCookie(cookies, api.AccessTokenCookieName)
			require.NotNil(t, access)
			assert.Equal(t, "access", access.Value)
			assert.Equal(t, mode.isSecure, access.Secure)
			refresh := findCookie(cookies, api.RefreshTokenCookieName)
			require.NotNil(t, refresh)
			assert.Equal(t, "refresh", refresh.Value)
			pending := findCookie(cookies, api.OAuthFlowCookieName(api.PendingSignupCookieName, mode.isSecure))
			require.NotNil(t, pending)
			assert.Less(t, pending.MaxAge, 0)
			authMock.AssertExpectations(t)
			auditMock.AssertExpectations(t)
		})
	}

	t.Run("error - missing pending cookie", func(t *testing.T) {
		controller, authMock, _, auditMock := newTestAuthControllerWithSignup(true)

		w, req := getControllerArgs("POST", "/auth/signup/verify", dto)

		controller.VerifySignup(w, req)

		var response api.ResponseBody[any]
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "auth.signup.noPending", response.Error)
		authMock.AssertNotCalled(t, "CompleteSignup", mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - development cookie name is ignored in secure mode", func(t *testing.T) {
		controller, authMock, _, _ := newTestAuthControllerWithSignup(true)

		w, req := getControllerArgs("POST", "/auth/signup/verify", dto)
		req = withPendingSignupCookie(req, false, "pending-uuid")

		controller.VerifySignup(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		authMock.AssertNotCalled(t, "CompleteSignup", mock.Anything, mock.Anything)
	})

	t.Run("error - invalid code format", func(t *testing.T) {
		controller, authMock, _, _ := newTestAuthControllerWithSignup(true)

		w, req := getControllerArgs("POST", "/auth/signup/verify", domain.CodeDTO{Code: "12ab"})
		req = withPendingSignupCookie(req, true, "pending-uuid")

		controller.VerifySignup(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		authMock.AssertNotCalled(t, "CompleteSignup", mock.Anything, mock.Anything)
	})

	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"invalid code", domain.ErrSignupInvalidCode, http.StatusUnauthorized},
		{"no pending signup", domain.ErrSignupNoPending, http.StatusUnauthorized},
		{"email taken", domain.NewConflictError("users.email.conflict"), http.StatusConflict},
		{"code locked", domain.ErrEmailCodeLocked, http.StatusTooManyRequests},
	} {
		t.Run("error - "+tc.name, func(t *testing.T) {
			controller, authMock, _, auditMock := newTestAuthControllerWithSignup(true)
			authMock.On("CompleteSignup", "pending-uuid", "123456").Return(nil, tc.err).Once()
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionUserCreate &&
					d.Status == domain.AuditStatusFailure &&
					d.FailureReason != nil
			})).Return(nil).Once()

			w, req := getControllerArgs("POST", "/auth/signup/verify", dto)
			req = withPendingSignupCookie(req, true, "pending-uuid")

			controller.VerifySignup(w, req)

			assert.Equal(t, tc.status, w.Code)
			assert.Nil(t, findCookie(w.Result().Cookies(), api.AccessTokenCookieName))
			assert.Nil(t, findCookie(w.Result().Cookies(), api.OAuthFlowCookieName(api.PendingSignupCookieName, true)))
			auditMock.AssertExpectations(t)
		})
	}
}

func TestAuthController_ResendSignup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, _, pendingMock, _ := newTestAuthControllerWithSignup(true)
		pendingMock.On("Resend", "pending-uuid").Return(nil).Once()

		w, req := getControllerArgs("POST", "/auth/signup/resend", nil)
		req = withPendingSignupCookie(req, true, "pending-uuid")

		controller.ResendSignup(w, req)

		var response api.ResponseBody[any]
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.Equal(t, "auth.signup.codeResent", response.Message)
		pendingMock.AssertExpectations(t)
	})

	t.Run("error - missing pending cookie", func(t *testing.T) {
		controller, _, pendingMock, _ := newTestAuthControllerWithSignup(true)

		w, req := getControllerArgs("POST", "/auth/signup/resend", nil)

		controller.ResendSignup(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		pendingMock.AssertNotCalled(t, "Resend", mock.Anything)
	})

	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"no pending signup", domain.ErrSignupNoPending, http.StatusUnauthorized},
		{"send limit", domain.ErrEmailSendLimit, http.StatusTooManyRequests},
	} {
		t.Run("error - "+tc.name, func(t *testing.T) {
			controller, _, pendingMock, _ := newTestAuthControllerWithSignup(true)
			pendingMock.On("Resend", "pending-uuid").Return(tc.err).Once()

			w, req := getControllerArgs("POST", "/auth/signup/resend", nil)
			req = withPendingSignupCookie(req, true, "pending-uuid")

			controller.ResendSignup(w, req)

			var response api.ResponseBody[any]
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, tc.err.Error(), response.Error)
		})
	}
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

	for _, mode := range oauthFlowCookieModes {
		t.Run("verification required - "+mode.name, func(t *testing.T) {
			controller, authServiceMock, auditMock := newTestAuthControllerWithOptions(mode.isSecure, []string{allowedRedirectURI})
			authServiceMock.On("OAuthLogin", domain.OAuthLoginDTO{
				Provider:     domain.OAuthProviderGoogle,
				State:        "valid-state",
				Code:         "auth-code",
				Nonce:        "nonce-123",
				CodeVerifier: "verifier-123",
			}).Return(&domain.OAuthLoginResult{
				PendingSignupUUID: "pending-uuid",
				RedirectURI:       "http://localhost:3000/callback?next=%2Fhome",
			}, nil).Once()
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionSignupRequest &&
					d.Status == domain.AuditStatusSuccess &&
					d.ResourceType == domain.AuditResourceAuth &&
					d.Changes.(map[string]string)["provider"] == "google" &&
					d.ResourceUUID == ""
			})).Return(nil).Once()

			w, req := getControllerArgs("GET", "/auth/google/callback?state=valid-state&code=auth-code", nil)
			req.SetPathValue("provider", string(domain.OAuthProviderGoogle))
			req.AddCookie(&http.Cookie{Name: mode.cookies.nonce, Value: "nonce-123"})
			req.AddCookie(&http.Cookie{Name: mode.cookies.verifier, Value: "verifier-123"})

			controller.OAuthProviderCallback(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, "http://localhost:3000/callback?next=%2Fhome&verification=required", w.Header().Get("Location"))
			cookies := w.Result().Cookies()
			pending := findCookie(cookies, api.OAuthFlowCookieName(api.PendingSignupCookieName, mode.isSecure))
			require.NotNil(t, pending)
			assert.Equal(t, "pending-uuid", pending.Value)
			assert.Nil(t, findCookie(cookies, "access_token"))
			assertOAuthFlowCookiesCleared(t, cookies, mode.cookies)
			authServiceMock.AssertExpectations(t)
			auditMock.AssertExpectations(t)
		})
	}

	t.Run("verification limited - redirects with error and sets no pending cookie", func(t *testing.T) {
		controller, authServiceMock, auditMock := newTestAuthController()
		authServiceMock.On("OAuthLogin", mock.Anything).Return(&domain.OAuthLoginResult{
			VerificationLimited: true,
			RedirectURI:         allowedRedirectURI,
		}, nil).Once()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionSignupRequest &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil && *d.FailureReason == "verification_limited"
		})).Return(nil).Once()

		w, req := getControllerArgs("GET", "/auth/github/callback?state=valid-state&code=auth-code", nil)
		req.SetPathValue("provider", string(domain.OAuthProviderGitHub))

		controller.OAuthProviderCallback(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, allowedRedirectURI+"?error=verification_limited", w.Header().Get("Location"))
		assert.Nil(t, findCookie(w.Result().Cookies(), api.OAuthFlowCookieName(api.PendingSignupCookieName, true)))
		auditMock.AssertExpectations(t)
	})

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
