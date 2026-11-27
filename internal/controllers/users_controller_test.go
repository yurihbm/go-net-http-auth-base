package controllers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func newTestUsersController() (*controllers.UsersController, *mocks.UsersServiceMock, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock) {
	controller, serviceMock, auditMock, middlewareMock, stepUpMiddlewareMock := newTestUsersControllerWithStepUp()
	stepUpMiddlewareMock.On("Use", mock.Anything).Return(mock.Anything).Maybe()
	return controller, serviceMock, auditMock, middlewareMock
}

func newTestEmailChangeController() (*controllers.UsersController, *mocks.EmailChangeServiceMock, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock) {
	emailChangeMock := new(mocks.EmailChangeServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	middlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.NewUsersController(new(mocks.UsersServiceMock), emailChangeMock, new(mocks.PendingSignupServiceMock), new(mocks.PasswordServiceMock), auditMock, middlewareMock, new(mocks.AuthMiddlewareMock), passthroughMiddleware{}, passthroughMiddleware{}, true)

	return controller, emailChangeMock, auditMock, middlewareMock
}

func newTestUsersControllerWithStepUp() (*controllers.UsersController, *mocks.UsersServiceMock, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock, *mocks.AuthMiddlewareMock) {
	serviceMock := new(mocks.UsersServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	middlewareMock := new(mocks.AuthMiddlewareMock)
	stepUpMiddlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.NewUsersController(serviceMock, new(mocks.EmailChangeServiceMock), new(mocks.PendingSignupServiceMock), new(mocks.PasswordServiceMock), auditMock, middlewareMock, stepUpMiddlewareMock, passthroughMiddleware{}, passthroughMiddleware{}, true)

	return controller, serviceMock, auditMock, middlewareMock, stepUpMiddlewareMock
}

func newTestSignupUsersController(isSecure bool) (*controllers.UsersController, *mocks.PendingSignupServiceMock, *mocks.AuditServiceMock) {
	pendingMock := new(mocks.PendingSignupServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	controller := controllers.NewUsersController(new(mocks.UsersServiceMock), new(mocks.EmailChangeServiceMock), pendingMock, new(mocks.PasswordServiceMock), auditMock, new(mocks.AuthMiddlewareMock), new(mocks.AuthMiddlewareMock), passthroughMiddleware{}, passthroughMiddleware{}, isSecure)

	return controller, pendingMock, auditMock
}

func newTestPasswordUsersController() (*controllers.UsersController, *mocks.PasswordServiceMock, *mocks.AuditServiceMock) {
	passwordMock := new(mocks.PasswordServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	controller := controllers.NewUsersController(new(mocks.UsersServiceMock), new(mocks.EmailChangeServiceMock), new(mocks.PendingSignupServiceMock), passwordMock, auditMock, new(mocks.AuthMiddlewareMock), new(mocks.AuthMiddlewareMock), passthroughMiddleware{}, passthroughMiddleware{}, true)

	return controller, passwordMock, auditMock
}

var actor = domain.Actor{UUID: "caller-uuid", Role: domain.RoleUser}

const actorSessionUUID = "caller-session-uuid"

func getActorControllerArgs(method string, endpoint string, body any) (*httptest.ResponseRecorder, *http.Request) {
	w, req := getControllerArgs(method, endpoint, body)
	ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{
		UserUUID:    actor.UUID,
		UserRole:    actor.Role,
		SessionUUID: actorSessionUUID,
	})
	return w, req.WithContext(ctx)
}

func TestUsersController_RegisterRoutes(t *testing.T) {
	t.Run("success - wraps GET /users with auth and role middlewares", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := new(mocks.AuthMiddlewareMock)
		roleMiddleware := new(mocks.AuthMiddlewareMock)
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(1)
		controller := controllers.NewUsersController(new(mocks.UsersServiceMock), new(mocks.EmailChangeServiceMock), new(mocks.PendingSignupServiceMock), new(mocks.PasswordServiceMock), new(mocks.AuditServiceMock), authMiddleware, authMiddleware, roleMiddleware, passthroughMiddleware{}, true)

		controller.RegisterRoutes(router)

		roleMiddleware.AssertNumberOfCalls(t, "Use", 1)
	})

	t.Run("should register routes with auth middleware", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, _, authMiddleware := newTestUsersController()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(8)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 8)
		for _, path := range []string{"/users", "/users/revert-email-change"} {
			_, pattern := router.Handler(httptest.NewRequest("POST", path, nil))
			assert.Equal(t, "POST "+path, pattern)
		}
		for _, path := range []string{"/users/verify-email", "/users/resend-verification"} {
			_, pattern := router.Handler(httptest.NewRequest("POST", path, nil))
			assert.NotEqual(t, "POST "+path, pattern)
		}
	})

	t.Run("should protect only email change, password change and deletion with step-up", func(t *testing.T) {
		router := http.NewServeMux()
		_, serviceMock, _, authMiddleware, _ := newTestUsersControllerWithStepUp()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		serviceMock.On("GetByUUID", mock.Anything, mock.Anything).Return(nil, errors.New("stop")).Maybe()
		serviceMock.On("List", mock.Anything).Return(nil, errors.New("stop")).Maybe()
		controller := controllers.NewUsersController(serviceMock, new(mocks.EmailChangeServiceMock), new(mocks.PendingSignupServiceMock), new(mocks.PasswordServiceMock), new(mocks.AuditServiceMock), authMiddleware, stepUpMarker{}, passthroughMiddleware{}, passthroughMiddleware{}, true)

		controller.RegisterRoutes(router)

		for _, route := range []struct {
			method, path string
			stepUp       bool
		}{
			{"POST", "/users", false},
			{"POST", "/users/revert-email-change", false},
			{"GET", "/users/me", false},
			{"POST", "/users/me/email", true},
			{"POST", "/users/me/email/confirm", false},
			{"POST", "/users/me/password", true},
			{"GET", "/users", false},
			{"GET", "/users/some-uuid", false},
			{"PUT", "/users/some-uuid", false},
			{"DELETE", "/users/some-uuid", true},
		} {
			w := httptest.NewRecorder()

			router.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))

			assert.Equal(t, route.stepUp, w.Header().Get(stepUpMarkerHeader) != "", route.method+" "+route.path)
		}
	})

	t.Run("success - credential routes are wrapped by the limiter", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := rejectingMiddleware{http.StatusUnauthorized}
		controller := controllers.NewUsersController(new(mocks.UsersServiceMock), new(mocks.EmailChangeServiceMock), new(mocks.PendingSignupServiceMock), new(mocks.PasswordServiceMock), new(mocks.AuditServiceMock), authMiddleware, authMiddleware, passthroughMiddleware{}, limiterMarker{}, true)
		controller.RegisterRoutes(router)

		for route, limited := range map[string]bool{
			"POST /users":                     true,
			"POST /users/revert-email-change": true,
			"GET /users/me":                   false,
			"POST /users/me/email/confirm":    false,
			"PUT /users/some-uuid":            false,
		} {
			parts := strings.SplitN(route, " ", 2)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, httptest.NewRequest(parts[0], parts[1], nil))

			assert.Equal(t, limited, w.Header().Get(limiterMarkerHeader) != "", route)
		}
	})
}

const stepUpMarkerHeader = "X-Step-Up-Applied"

type stepUpMarker struct{}

func (stepUpMarker) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(stepUpMarkerHeader, "true")
		w.WriteHeader(http.StatusTeapot)
	}
}

func TestUsersController_CreateUser(t *testing.T) {
	dto := domain.CreateUserDTO{
		Name:     "John Doe",
		Email:    "john.doe@example.com",
		Password: "password123",
	}

	for _, mode := range []struct {
		name       string
		isSecure   bool
		cookieName string
	}{
		{"secure", true, "__Host-pending_signup"},
		{"development", false, "pending_signup"},
	} {
		t.Run("success sets the pending signup cookie - "+mode.name, func(t *testing.T) {
			controller, pendingMock, auditMock := newTestSignupUsersController(mode.isSecure)
			pendingMock.On("StartCredentials", dto).Return("pending-uuid", nil).Once()
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionSignupRequest &&
					d.ResourceType == domain.AuditResourceUser &&
					d.ResourceUUID == "" &&
					d.Status == domain.AuditStatusSuccess
			})).Return(nil).Once()

			w, req := getControllerArgs("POST", "/users", dto)

			controller.CreateUser(w, req)

			var response api.ResponseBody[any]
			assert.Nil(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, http.StatusAccepted, w.Code)
			assert.Equal(t, "user.create.pending", response.Message)
			assert.Nil(t, response.Data)
			cookie := findCookie(w.Result().Cookies(), mode.cookieName)
			if assert.NotNil(t, cookie) {
				assert.Equal(t, "pending-uuid", cookie.Value)
				assert.Equal(t, "/", cookie.Path)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
				assert.Equal(t, mode.isSecure, cookie.Secure)
			}
			pendingMock.AssertExpectations(t)
			auditMock.AssertExpectations(t)
		})
	}

	t.Run("bad request - short password", func(t *testing.T) {
		controller, pendingMock, auditMock := newTestSignupUsersController(true)

		w, req := getControllerArgs("POST", "/users", domain.CreateUserDTO{Name: "John Doe", Email: "john@mail.com", Password: "1234556"})

		controller.CreateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		pendingMock.AssertNotCalled(t, "StartCredentials", mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("bad request - password longer than bcrypt accepts", func(t *testing.T) {
		controller, pendingMock, auditMock := newTestSignupUsersController(true)

		w, req := getControllerArgs("POST", "/users", domain.CreateUserDTO{Name: "John Doe", Email: "john@mail.com", Password: strings.Repeat("a", 73)})

		controller.CreateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		pendingMock.AssertNotCalled(t, "StartCredentials", mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("bad request - unknown fields", func(t *testing.T) {
		controller, pendingMock, auditMock := newTestSignupUsersController(true)

		w, req := getControllerArgs("POST", "/users", struct{ Test string }{Test: "invalid"})

		controller.CreateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		pendingMock.AssertNotCalled(t, "StartCredentials", mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"conflict", domain.NewConflictError("users.email.conflict"), http.StatusConflict},
		{"send limit", domain.ErrEmailSendLimit, http.StatusTooManyRequests},
		{"send failure", domain.NewInternalServerError("auth.signup.sendFailed", errors.New("smtp down")), http.StatusInternalServerError},
	} {
		t.Run("error - "+tc.name, func(t *testing.T) {
			controller, pendingMock, auditMock := newTestSignupUsersController(true)
			pendingMock.On("StartCredentials", dto).Return("", tc.err).Once()
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionSignupRequest &&
					d.Status == domain.AuditStatusFailure &&
					d.FailureReason != nil
			})).Return(nil).Once()

			w, req := getControllerArgs("POST", "/users", dto)

			controller.CreateUser(w, req)

			assert.Equal(t, tc.status, w.Code)
			assert.Nil(t, findCookie(w.Result().Cookies(), "__Host-pending_signup"))
			auditMock.AssertExpectations(t)
		})
	}
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
		serviceMock.On("GetByUUID", domain.Actor{UUID: "test-uuid"}, "test-uuid").Return(user, nil)

		w, req := getControllerArgs("GET", "/users/me", nil)
		// Inject user UUID into context
		ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{
			UserUUID: "test-uuid",
		})
		req = req.WithContext(ctx)

		controller.GetMe(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *user, response.Data)
		assert.Equal(t, domain.RoleUser, response.Data.Role)
		serviceMock.AssertCalled(t, "GetByUUID", domain.Actor{UUID: "test-uuid"}, "test-uuid")
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
		serviceMock.On("GetByUUID", domain.Actor{UUID: "test-uuid"}, "test-uuid").Return(nil,
			domain.NewNotFoundError(
				"user.notFound",
			),
		)

		w, req := getControllerArgs("GET", "/users/me", nil)
		ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{
			UserUUID: "test-uuid",
		})
		req = req.WithContext(ctx)

		controller.GetMe(w, req)

		var response api.ResponseBody[any]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertCalled(t, "GetByUUID", domain.Actor{UUID: "test-uuid"}, "test-uuid")
	})
}

func TestUsersController_GetUserByUUID(t *testing.T) {
	uuid := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	user := &domain.User{
		UUID:  uuid,
		Name:  "John Doe",
		Email: "john.doe@example.com",
		Role:  domain.RoleUser,
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()

		serviceMock.On("GetByUUID", actor, uuid).Return(user, nil)

		w, req := getActorControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *user, response.Data)
		assert.Equal(t, domain.RoleUser, response.Data.Role)
		serviceMock.AssertCalled(t, "GetByUUID", actor, uuid)
	})

	t.Run("success - uppercase UUID is passed in canonical form", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("GetByUUID", actor, uuid).Return(user, nil)

		w, req := getActorControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", strings.ToUpper(uuid))

		controller.GetUserByUUID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "GetByUUID", actor, uuid)
	})

	t.Run("error - invalid UUID", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()

		w, req := getActorControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", "not-a-uuid")

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "users.invalidUserUUID", response.Error)
		serviceMock.AssertNotCalled(t, "GetByUUID", mock.Anything, mock.Anything)
	})

	t.Run("not found", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()

		serviceMock.On("GetByUUID", actor, uuid).Return(
			nil,
			domain.NewNotFoundError("user.notFound"),
		)

		w, req := getActorControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, response.Message)
		assert.Empty(t, response.Data)
		assert.NotEmpty(t, response.Error)
		serviceMock.AssertCalled(t, "GetByUUID", actor, uuid)
	})

	t.Run("forbidden", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("GetByUUID", actor, uuid).Return(nil, domain.NewForbiddenError("users.forbidden"))

		w, req := getActorControllerArgs("GET", "/users/", nil)
		req.SetPathValue("uuid", uuid)

		controller.GetUserByUUID(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestUsersController_UpdateUser(t *testing.T) {
	uuid := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	name := "John Updated"
	dto := domain.UserUpdateDTO{Name: &name}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		updatedUser := &domain.User{UUID: uuid, Name: name}
		serviceMock.On("Update", actor, uuid, dto).Return(updatedUser, nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserUpdate &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == uuid &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getActorControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		var response api.ResponseBody[domain.User]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, *updatedUser, response.Data)
		serviceMock.AssertCalled(t, "Update", actor, uuid, dto)
		auditMock.AssertExpectations(t)
	})

	t.Run("success - uppercase UUID is passed in canonical form", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()
		serviceMock.On("Update", actor, uuid, dto).Return(&domain.User{UUID: uuid, Name: name}, nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.ResourceUUID == uuid && d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getActorControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", strings.ToUpper(uuid))

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertCalled(t, "Update", actor, uuid, dto)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid UUID", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := getActorControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", "not-a-uuid")

		controller.UpdateUser(w, req)

		var response api.ResponseBody[any]
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "users.invalidUserUUID", response.Error)
		serviceMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("bad request", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := getActorControllerArgs("PUT", "/users/", struct {
			Test string
		}{Test: "test"})
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Update")
		auditMock.AssertNotCalled(t, "Log")
	})

	t.Run("error - email is not updatable", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := getActorControllerArgs("PUT", "/users/", map[string]string{"email": "new@example.com"})
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Update", actor, uuid, dto).Return(nil, assert.AnError)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserUpdate &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

		w, req := getActorControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Update", actor, uuid, dto)
		auditMock.AssertExpectations(t)
	})

	t.Run("forbidden", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()
		serviceMock.On("Update", actor, uuid, dto).Return(nil, domain.NewForbiddenError("users.forbidden"))
		auditMock.On("Log", mock.Anything).Return(nil)

		w, req := getActorControllerArgs("PUT", "/users/", dto)
		req.SetPathValue("uuid", uuid)

		controller.UpdateUser(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestUsersController_DeleteUser(t *testing.T) {
	const otherUUID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	const selfUUID = "0190f1e2-d3c4-7b5a-8978-6f5e4d3c2b1a"
	self := domain.Actor{UUID: selfUUID, Role: domain.RoleUser}
	forbidden := domain.NewForbiddenError("users.forbidden")

	newRequest := func(pathUUID string) (*httptest.ResponseRecorder, *http.Request) {
		w, req := getControllerArgs("DELETE", "/users/", nil)
		ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{
			UserUUID:    self.UUID,
			UserRole:    self.Role,
			SessionUUID: actorSessionUUID,
		})
		req = req.WithContext(ctx)
		req.SetPathValue("uuid", pathUUID)
		return w, req
	}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Delete", self, otherUUID).Return(nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserDelete &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == otherUUID &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := newRequest(otherUUID)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Result().Cookies())
		serviceMock.AssertCalled(t, "Delete", self, otherUUID)
		auditMock.AssertExpectations(t)
	})

	t.Run("success - deleting own account clears the auth cookies", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()
		serviceMock.On("Delete", self, selfUUID).Return(nil)
		auditMock.On("Log", mock.Anything).Return(nil)

		w, req := newRequest(selfUUID)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		cookies := w.Result().Cookies()
		for _, name := range []string{api.AccessTokenCookieName, api.RefreshTokenCookieName} {
			cookie := findCookie(cookies, name)
			require.NotNil(t, cookie, name)
			assert.Equal(t, -1, cookie.MaxAge, name)
		}
	})

	for name, pathUUID := range map[string]string{
		"uppercase":      strings.ToUpper(selfUUID),
		"without hyphen": strings.ReplaceAll(selfUUID, "-", ""),
		"braced":         "{" + selfUUID + "}",
		"urn":            "urn:uuid:" + selfUUID,
	} {
		t.Run("success - own account as "+name+" clears the auth cookies and passes the canonical UUID", func(t *testing.T) {
			controller, serviceMock, auditMock, _ := newTestUsersController()
			serviceMock.On("Delete", self, selfUUID).Return(nil)
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.ResourceUUID == selfUUID
			})).Return(nil)

			w, req := newRequest(pathUUID)

			controller.DeleteUser(w, req)

			assert.Equal(t, http.StatusNoContent, w.Code)
			assert.NotNil(t, findCookie(w.Result().Cookies(), api.AccessTokenCookieName))
			assert.NotNil(t, findCookie(w.Result().Cookies(), api.RefreshTokenCookieName))
			serviceMock.AssertCalled(t, "Delete", self, selfUUID)
			auditMock.AssertExpectations(t)
		})
	}

	t.Run("error - invalid UUID", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		w, req := newRequest("not-a-uuid")

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, w.Result().Cookies())
		serviceMock.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - failed self deletion keeps the auth cookies", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()
		serviceMock.On("Delete", self, selfUUID).Return(domain.NewConflictError("users.emailChange.locked"))
		auditMock.On("Log", mock.Anything).Return(nil)

		w, req := newRequest(selfUUID)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("service error", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()

		serviceMock.On("Delete", self, otherUUID).Return(assert.AnError)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionUserDelete &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

		w, req := newRequest(otherUUID)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		serviceMock.AssertCalled(t, "Delete", self, otherUUID)
		auditMock.AssertExpectations(t)
	})

	t.Run("forbidden", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestUsersController()
		serviceMock.On("Delete", self, otherUUID).Return(forbidden)
		auditMock.On("Log", mock.Anything).Return(nil)

		w, req := newRequest(otherUUID)

		controller.DeleteUser(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestUsersController_RequestEmailChange(t *testing.T) {
	dto := domain.RequestEmailChangeDTO{Email: "new@example.com"}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()
		serviceMock.On("RequestEmailChange", actor, actorSessionUUID, dto.Email).Return(nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionEmailChangeRequest &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == actor.UUID &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getActorControllerArgs("POST", "/users/me/email", dto)

		controller.RequestEmailChange(w, req)

		var response api.ResponseBody[any]
		assert.Nil(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusAccepted, w.Code)
		assert.Equal(t, "user.emailChange.requested", response.Message)
		serviceMock.AssertExpectations(t)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid email", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()

		w, req := getActorControllerArgs("POST", "/users/me/email", domain.RequestEmailChangeDTO{Email: "not-an-email"})

		controller.RequestEmailChange(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "RequestEmailChange", mock.Anything, mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - email taken", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()
		serviceMock.On("RequestEmailChange", actor, actorSessionUUID, dto.Email).Return(domain.NewConflictError("users.email.conflict"))
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionEmailChangeRequest &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil)

		w, req := getActorControllerArgs("POST", "/users/me/email", dto)

		controller.RequestEmailChange(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		auditMock.AssertExpectations(t)
	})
}

func TestUsersController_ConfirmEmailChange(t *testing.T) {
	dto := domain.CodeDTO{Code: "123456"}
	user := &domain.User{UUID: actor.UUID, Email: "new@example.com"}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()
		serviceMock.On("ConfirmEmailChange", actor, actorSessionUUID, dto.Code).Return(user, nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionEmailChange &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == user.UUID &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getActorControllerArgs("POST", "/users/me/email/confirm", dto)

		controller.ConfirmEmailChange(w, req)

		var response api.ResponseBody[domain.User]
		assert.Nil(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "user.emailChange.success", response.Message)
		assert.Equal(t, *user, response.Data)
		assertAuthCookiesCleared(t, w)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid code", func(t *testing.T) {
		for name, code := range map[string]string{"missing": "", "too short": "123", "not numeric": "12345a"} {
			controller, serviceMock, auditMock, _ := newTestEmailChangeController()

			w, req := getActorControllerArgs("POST", "/users/me/email/confirm", domain.CodeDTO{Code: code})

			controller.ConfirmEmailChange(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code, name)
			serviceMock.AssertNotCalled(t, "ConfirmEmailChange", mock.Anything, mock.Anything, mock.Anything)
			auditMock.AssertNotCalled(t, "Log", mock.Anything)
		}
	})

	failures := map[string]struct {
		err    error
		status int
	}{
		"wrong code":       {domain.ErrEmailChangeInvalidCode, http.StatusUnauthorized},
		"no challenge":     {domain.ErrEmailChangeNoChallenge, http.StatusUnauthorized},
		"stale":            {domain.NewUnauthorizedError("users.emailChange.staleToken"), http.StatusUnauthorized},
		"address locked":   {domain.ErrEmailCodeLocked, http.StatusTooManyRequests},
		"email taken":      {domain.NewConflictError("users.email.conflict"), http.StatusConflict},
		"change lock held": {domain.NewConflictError("users.emailChange.locked"), http.StatusConflict},
	}
	for name, tc := range failures {
		t.Run("error - "+name, func(t *testing.T) {
			controller, serviceMock, auditMock, _ := newTestEmailChangeController()
			serviceMock.On("ConfirmEmailChange", actor, actorSessionUUID, dto.Code).Return(nil, tc.err)
			auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
				return d.Action == domain.AuditActionEmailChange &&
					d.Status == domain.AuditStatusFailure &&
					d.FailureReason != nil
			})).Return(nil)

			w, req := getActorControllerArgs("POST", "/users/me/email/confirm", dto)

			controller.ConfirmEmailChange(w, req)

			assert.Equal(t, tc.status, w.Code)
			assert.Empty(t, w.Result().Cookies())
			auditMock.AssertExpectations(t)
		})
	}
}

func assertAuthCookiesCleared(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	cleared := map[string]int{}
	for _, cookie := range w.Result().Cookies() {
		cleared[cookie.Name] = cookie.MaxAge
	}
	assert.Equal(t, map[string]int{api.AccessTokenCookieName: -1, api.RefreshTokenCookieName: -1}, cleared)
}

func TestUsersController_RevertEmailChange(t *testing.T) {
	dto := domain.RevertEmailChangeDTO{Token: "revert-token"}
	restored := &domain.User{UUID: "user-uuid", Email: "old@example.com"}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()
		serviceMock.On("RevertEmailChange", dto.Token).Return(restored, nil)
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionEmailChangeRevert &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == restored.UUID &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil)

		w, req := getControllerArgs("POST", "/users/revert-email-change", dto)

		controller.RevertEmailChange(w, req)

		var response api.ResponseBody[any]
		assert.Nil(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "user.emailChange.reverted", response.Message)
		assertAuthCookiesCleared(t, w)
		serviceMock.AssertCalled(t, "RevertEmailChange", dto.Token)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - missing token", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()

		w, req := getControllerArgs("POST", "/users/revert-email-change", domain.RevertEmailChangeDTO{})

		controller.RevertEmailChange(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "RevertEmailChange", mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - stale token", func(t *testing.T) {
		controller, serviceMock, auditMock, _ := newTestEmailChangeController()
		serviceMock.On("RevertEmailChange", dto.Token).Return(nil, domain.NewUnauthorizedError("users.emailChange.staleToken"))

		w, req := getControllerArgs("POST", "/users/revert-email-change", dto)

		controller.RevertEmailChange(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, w.Result().Cookies())
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - old email taken", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestEmailChangeController()
		serviceMock.On("RevertEmailChange", dto.Token).Return(nil, domain.NewConflictError("users.email.conflict"))

		w, req := getControllerArgs("POST", "/users/revert-email-change", dto)

		controller.RevertEmailChange(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

func TestUsersController_ChangePassword(t *testing.T) {
	dto := domain.ChangePasswordDTO{NewPassword: "new-password-1"}

	t.Run("success", func(t *testing.T) {
		controller, passwordMock, auditMock := newTestPasswordUsersController()
		passwordMock.On("ChangePassword", actor, actorSessionUUID, dto).Return(nil).Once()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionPasswordChange &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == actor.UUID &&
				d.ActorUUID != nil && *d.ActorUUID == actor.UUID &&
				d.Status == domain.AuditStatusSuccess
		})).Return(nil).Once()

		w, req := getActorControllerArgs("POST", "/users/me/password", dto)

		controller.ChangePassword(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		passwordMock.AssertExpectations(t)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - password too short", func(t *testing.T) {
		controller, passwordMock, auditMock := newTestPasswordUsersController()

		w, req := getActorControllerArgs("POST", "/users/me/password", domain.ChangePasswordDTO{NewPassword: "short"})

		controller.ChangePassword(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		passwordMock.AssertNotCalled(t, "ChangePassword", mock.Anything, mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - service failure is audited", func(t *testing.T) {
		controller, passwordMock, auditMock := newTestPasswordUsersController()
		passwordMock.On("ChangePassword", actor, actorSessionUUID, dto).Return(domain.NewInternalServerError("users.password.hashingFailed", errors.New("boom"))).Once()
		auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			return d.Action == domain.AuditActionPasswordChange &&
				d.Status == domain.AuditStatusFailure &&
				d.FailureReason != nil
		})).Return(nil).Once()

		w, req := getActorControllerArgs("POST", "/users/me/password", dto)

		controller.ChangePassword(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		auditMock.AssertExpectations(t)
	})
}

func TestUsersController_ListUsers(t *testing.T) {
	items := []domain.User{{UUID: "019623b0-0000-7000-8000-000000000001", Name: "Jane Doe", Email: "jane@example.com", Role: domain.RoleUser}}
	nextCursor := "019623b0-0000-7000-8000-000000000001"

	t.Run("success with defaults", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("List", mock.MatchedBy(func(dto domain.ListUsersDTO) bool {
			return dto.Limit == 20 && dto.Search == nil && dto.Role == nil && dto.Cursor == nil
		})).Return(&domain.Page[domain.User]{Items: items, NextCursor: &nextCursor, Total: 1}, nil)
		w, req := getControllerArgs("GET", "/users", nil)

		controller.ListUsers(w, req)

		var response api.ResponseBody[[]domain.User]
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, items, response.Data)
		assert.Equal(t, "users.list.success", response.Message)
		require.NotNil(t, response.Meta)
		assert.Equal(t, int64(1), response.Meta.Total)
		assert.Equal(t, 20, response.Meta.Limit)
		assert.Equal(t, &nextCursor, response.Meta.NextCursor)
		serviceMock.AssertExpectations(t)
	})

	t.Run("success with all filters", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("List", mock.MatchedBy(func(dto domain.ListUsersDTO) bool {
			return dto.Limit == 10 &&
				dto.Search != nil && *dto.Search == "jan" &&
				dto.Role != nil && *dto.Role == domain.RoleAdmin &&
				dto.Cursor != nil && *dto.Cursor == nextCursor
		})).Return(&domain.Page[domain.User]{Items: items, Total: 1}, nil)
		w, req := getControllerArgs("GET", "/users", nil)
		req.URL.RawQuery = url.Values{"search": {"jan"}, "role": {"admin"}, "cursor": {nextCursor}, "limit": {"10"}}.Encode()

		controller.ListUsers(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertExpectations(t)
	})

	t.Run("success - search is trimmed", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("List", mock.MatchedBy(func(dto domain.ListUsersDTO) bool {
			return dto.Search != nil && *dto.Search == "jan"
		})).Return(&domain.Page[domain.User]{Items: items, Total: 1}, nil)
		w, req := getControllerArgs("GET", "/users", nil)
		req.URL.RawQuery = url.Values{"search": {"  jan "}}.Encode()

		controller.ListUsers(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertExpectations(t)
	})

	t.Run("success - blank search means no search", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("List", mock.MatchedBy(func(dto domain.ListUsersDTO) bool {
			return dto.Search == nil
		})).Return(&domain.Page[domain.User]{Items: items, Total: 1}, nil)
		w, req := getControllerArgs("GET", "/users", nil)
		req.URL.RawQuery = url.Values{"search": {"   "}}.Encode()

		controller.ListUsers(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertExpectations(t)
	})

	for name, query := range map[string]url.Values{
		"invalid limit - not a number":     {"limit": {"abc"}},
		"invalid limit - out of range 0":   {"limit": {"0"}},
		"invalid limit - out of range 101": {"limit": {"101"}},
		"invalid role":                     {"role": {"root"}},
		"search with NUL byte":             {"search": {"ja\x00n"}},
		"search with invalid UTF-8":        {"search": {"ja\xffn"}},
	} {
		t.Run("error - "+name, func(t *testing.T) {
			controller, serviceMock, _, _ := newTestUsersController()
			w, req := getControllerArgs("GET", "/users", nil)
			req.URL.RawQuery = query.Encode()

			controller.ListUsers(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "users.list.badRequest")
			serviceMock.AssertNotCalled(t, "List")
		})
	}

	t.Run("error - service error", func(t *testing.T) {
		controller, serviceMock, _, _ := newTestUsersController()
		serviceMock.On("List", mock.Anything).Return(nil, domain.NewInternalServerError("users.internalServerError", errors.New("boom")))
		w, req := getControllerArgs("GET", "/users", nil)

		controller.ListUsers(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
