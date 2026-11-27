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

const (
	testFlagUUID      = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	testFlagUserUUID  = "0190f1e2-d3c4-7b5a-8978-6f5e4d3c2b1a"
	testFlagAdminUUID = "0190c0de-0000-7000-8000-000000000001"
)

func newTestFeatureFlagsController() (*controllers.FeatureFlagsController, *mocks.FeatureFlagsServiceMock, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock, *mocks.AuthMiddlewareMock) {
	serviceMock := new(mocks.FeatureFlagsServiceMock)
	auditMock := new(mocks.AuditServiceMock)
	authMiddlewareMock := new(mocks.AuthMiddlewareMock)
	adminRoleMiddlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.NewFeatureFlagsController(serviceMock, auditMock, authMiddlewareMock, adminRoleMiddlewareMock)
	return controller, serviceMock, auditMock, authMiddlewareMock, adminRoleMiddlewareMock
}

func newFeatureFlagsRequest(method string, endpoint string, body any, pathValues map[string]string) (*httptest.ResponseRecorder, *http.Request) {
	w, req := getControllerArgs(method, endpoint, body)
	ctx := context.WithValue(req.Context(), shared.RequestContextDataKey, &shared.RequestContextData{
		UserUUID: testFlagAdminUUID,
		UserRole: domain.RoleAdmin,
	})
	req = req.WithContext(ctx)
	for name, value := range pathValues {
		req.SetPathValue(name, value)
	}
	return w, req
}

func matchFeatureFlagAudit(action string, status string, resourceUUID string, changes any) any {
	return mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
		return d.Action == action &&
			d.ResourceType == domain.AuditResourceFeatureFlag &&
			d.Status == status &&
			d.ResourceUUID == resourceUUID &&
			d.ActorUUID != nil && *d.ActorUUID == testFlagAdminUUID &&
			assert.ObjectsAreEqual(changes, d.Changes) &&
			(status == domain.AuditStatusSuccess) == (d.FailureReason == nil)
	})
}

func decodeBody[T any](t *testing.T, w *httptest.ResponseRecorder) api.ResponseBody[T] {
	t.Helper()
	var response api.ResponseBody[T]
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	return response
}

func TestNewFeatureFlagsController(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, _, _, _, _ := newTestFeatureFlagsController()

		assert.NotNil(t, controller)
	})
}

func TestFeatureFlagsController_RegisterRoutes(t *testing.T) {
	t.Run("success - every route has the auth and admin role middlewares", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, _, authMiddleware, adminRoleMiddleware := newTestFeatureFlagsController()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		adminRoleMiddleware.On("Use", mock.Anything).Return(mock.Anything)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 7)
		adminRoleMiddleware.AssertNumberOfCalls(t, "Use", 7)
	})
}

func TestFeatureFlagsController_CreateFeatureFlag(t *testing.T) {
	dto := domain.CreateFeatureFlagDTO{Key: "new-dashboard", Description: "Redesigned dashboard", EnabledGlobally: true}
	created := &domain.FeatureFlag{UUID: testFlagUUID, Key: "new-dashboard", Description: "Redesigned dashboard", EnabledGlobally: true}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("Create", dto).Return(created, nil)
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagCreate, domain.AuditStatusSuccess, testFlagUUID, dto)).Return(nil)
		w, req := newFeatureFlagsRequest("POST", "/feature-flags", dto, nil)

		controller.CreateFeatureFlag(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		response := decodeBody[domain.FeatureFlag](t, w)
		assert.Equal(t, "featureFlags.create.success", response.Message)
		assert.Equal(t, *created, response.Data)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid key", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("POST", "/feature-flags", map[string]any{"key": "Not Valid"}, nil)

		controller.CreateFeatureFlag(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		response := decodeBody[any](t, w)
		assert.Equal(t, "request.validationFailed", response.Error)
		assert.NotEmpty(t, response.Details["key"])
		serviceMock.AssertNotCalled(t, "Create", mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - key conflict is audited as a failure", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("Create", dto).Return(nil, domain.NewConflictError("featureFlags.key.conflict"))
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagCreate, domain.AuditStatusFailure, "", dto)).Return(nil)
		w, req := newFeatureFlagsRequest("POST", "/feature-flags", dto, nil)

		controller.CreateFeatureFlag(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Equal(t, "featureFlags.key.conflict", decodeBody[any](t, w).Error)
		auditMock.AssertExpectations(t)
	})
}

func TestFeatureFlagsController_ListFeatureFlags(t *testing.T) {
	items := []domain.FeatureFlag{{UUID: testFlagUUID, Key: "beta"}}
	nextCursor := testFlagUUID

	t.Run("success - defaults", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		page := &domain.Page[domain.FeatureFlag]{Items: items, NextCursor: &nextCursor, Total: 3}
		serviceMock.On("List", domain.ListFeatureFlagsDTO{Limit: 20}).Return(page, nil)
		w, req := newFeatureFlagsRequest("GET", "/feature-flags", nil, nil)

		controller.ListFeatureFlags(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		response := decodeBody[[]domain.FeatureFlag](t, w)
		assert.Equal(t, "featureFlags.list.success", response.Message)
		assert.Equal(t, items, response.Data)
		require.NotNil(t, response.Meta)
		assert.Equal(t, int64(3), response.Meta.Total)
		assert.Equal(t, 20, response.Meta.Limit)
		assert.Equal(t, &nextCursor, response.Meta.NextCursor)
		serviceMock.AssertExpectations(t)
	})

	t.Run("success - limit and cursor are forwarded", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		cursor := testFlagUserUUID
		serviceMock.On("List", domain.ListFeatureFlagsDTO{Cursor: &cursor, Limit: 5}).Return(&domain.Page[domain.FeatureFlag]{}, nil)
		w, req := newFeatureFlagsRequest("GET", "/feature-flags?limit=5&cursor="+cursor, nil, nil)

		controller.ListFeatureFlags(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		serviceMock.AssertExpectations(t)
	})

	t.Run("error - invalid limit", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("GET", "/feature-flags?limit=0", nil, nil)

		controller.ListFeatureFlags(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "featureFlags.list.badRequest", decodeBody[any](t, w).Error)
		serviceMock.AssertNotCalled(t, "List", mock.Anything)
	})

	t.Run("error - service failure", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		serviceMock.On("List", domain.ListFeatureFlagsDTO{Limit: 20}).Return(nil, domain.NewInternalServerError("featureFlags.internalServerError", errors.New("boom")))
		w, req := newFeatureFlagsRequest("GET", "/feature-flags", nil, nil)

		controller.ListFeatureFlags(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestFeatureFlagsController_GetFeatureFlag(t *testing.T) {
	pathValues := map[string]string{"uuid": testFlagUUID}

	t.Run("success - includes the allow-list", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		details := &domain.FeatureFlagDetails{
			UUID:      testFlagUUID,
			Key:       "beta",
			UserUUIDs: []string{testFlagUserUUID},
		}
		serviceMock.On("GetByUUID", testFlagUUID).Return(details, nil)
		w, req := newFeatureFlagsRequest("GET", "/feature-flags/"+testFlagUUID, nil, pathValues)

		controller.GetFeatureFlag(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		response := decodeBody[domain.FeatureFlagDetails](t, w)
		assert.Equal(t, "featureFlags.get.success", response.Message)
		assert.Equal(t, *details, response.Data)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("GET", "/feature-flags/nope", nil, map[string]string{"uuid": "nope"})

		controller.GetFeatureFlag(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "featureFlags.invalidFlagUUID", decodeBody[any](t, w).Error)
		serviceMock.AssertNotCalled(t, "GetByUUID", mock.Anything)
	})

	t.Run("error - not found", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		serviceMock.On("GetByUUID", testFlagUUID).Return(nil, domain.NewNotFoundError("featureFlags.notFound"))
		w, req := newFeatureFlagsRequest("GET", "/feature-flags/"+testFlagUUID, nil, pathValues)

		controller.GetFeatureFlag(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "featureFlags.notFound", decodeBody[any](t, w).Error)
	})
}

func TestFeatureFlagsController_UpdateFeatureFlag(t *testing.T) {
	enabled := true
	dto := domain.UpdateFeatureFlagDTO{EnabledGlobally: &enabled}
	pathValues := map[string]string{"uuid": testFlagUUID}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		updated := &domain.FeatureFlag{UUID: testFlagUUID, Key: "beta", EnabledGlobally: true}
		serviceMock.On("Update", testFlagUUID, dto).Return(updated, nil)
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagUpdate, domain.AuditStatusSuccess, testFlagUUID, dto)).Return(nil)
		w, req := newFeatureFlagsRequest("PATCH", "/feature-flags/"+testFlagUUID, dto, pathValues)

		controller.UpdateFeatureFlag(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		response := decodeBody[domain.FeatureFlag](t, w)
		assert.Equal(t, "featureFlags.update.success", response.Message)
		assert.Equal(t, *updated, response.Data)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("PATCH", "/feature-flags/nope", dto, map[string]string{"uuid": "nope"})

		controller.UpdateFeatureFlag(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - unknown field", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("PATCH", "/feature-flags/"+testFlagUUID, map[string]any{"key": "renamed"}, pathValues)

		controller.UpdateFeatureFlag(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "request.invalid", decodeBody[any](t, w).Error)
		serviceMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
	})

	t.Run("error - not found is audited as a failure", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("Update", testFlagUUID, dto).Return(nil, domain.NewNotFoundError("featureFlags.notFound"))
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagUpdate, domain.AuditStatusFailure, testFlagUUID, dto)).Return(nil)
		w, req := newFeatureFlagsRequest("PATCH", "/feature-flags/"+testFlagUUID, dto, pathValues)

		controller.UpdateFeatureFlag(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		auditMock.AssertExpectations(t)
	})
}

func TestFeatureFlagsController_DeleteFeatureFlag(t *testing.T) {
	pathValues := map[string]string{"uuid": testFlagUUID}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("Delete", testFlagUUID).Return(nil)
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagDelete, domain.AuditStatusSuccess, testFlagUUID, nil)).Return(nil)
		w, req := newFeatureFlagsRequest("DELETE", "/feature-flags/"+testFlagUUID, nil, pathValues)

		controller.DeleteFeatureFlag(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Empty(t, w.Body.String())
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("DELETE", "/feature-flags/nope", nil, map[string]string{"uuid": "nope"})

		controller.DeleteFeatureFlag(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "Delete", mock.Anything)
		auditMock.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - not found is audited as a failure", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("Delete", testFlagUUID).Return(domain.NewNotFoundError("featureFlags.notFound"))
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagDelete, domain.AuditStatusFailure, testFlagUUID, nil)).Return(nil)
		w, req := newFeatureFlagsRequest("DELETE", "/feature-flags/"+testFlagUUID, nil, pathValues)

		controller.DeleteFeatureFlag(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		auditMock.AssertExpectations(t)
	})
}

func TestFeatureFlagsController_AddFeatureFlagUser(t *testing.T) {
	pathValues := map[string]string{"uuid": testFlagUUID, "userUuid": testFlagUserUUID}
	changes := map[string]string{"user_uuid": testFlagUserUUID}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("AddUser", testFlagUUID, testFlagUserUUID).Return(nil)
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagUserAdd, domain.AuditStatusSuccess, testFlagUUID, changes)).Return(nil)
		w, req := newFeatureFlagsRequest("PUT", "/feature-flags/"+testFlagUUID+"/users/"+testFlagUserUUID, nil, pathValues)

		controller.AddFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid flag uuid", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("PUT", "/feature-flags/nope/users/"+testFlagUserUUID, nil, map[string]string{"uuid": "nope", "userUuid": testFlagUserUUID})

		controller.AddFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "featureFlags.invalidFlagUUID", decodeBody[any](t, w).Error)
		serviceMock.AssertNotCalled(t, "AddUser", mock.Anything, mock.Anything)
	})

	t.Run("error - invalid user uuid", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("PUT", "/feature-flags/"+testFlagUUID+"/users/nope", nil, map[string]string{"uuid": testFlagUUID, "userUuid": "nope"})

		controller.AddFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "users.invalidUserUUID", decodeBody[any](t, w).Error)
		serviceMock.AssertNotCalled(t, "AddUser", mock.Anything, mock.Anything)
	})

	t.Run("error - user not found is audited as a failure", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("AddUser", testFlagUUID, testFlagUserUUID).Return(domain.NewNotFoundError("users.notFound"))
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagUserAdd, domain.AuditStatusFailure, testFlagUUID, changes)).Return(nil)
		w, req := newFeatureFlagsRequest("PUT", "/feature-flags/"+testFlagUUID+"/users/"+testFlagUserUUID, nil, pathValues)

		controller.AddFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "users.notFound", decodeBody[any](t, w).Error)
		auditMock.AssertExpectations(t)
	})
}

func TestFeatureFlagsController_RemoveFeatureFlagUser(t *testing.T) {
	pathValues := map[string]string{"uuid": testFlagUUID, "userUuid": testFlagUserUUID}
	changes := map[string]string{"user_uuid": testFlagUserUUID}

	t.Run("success", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("RemoveUser", testFlagUUID, testFlagUserUUID).Return(nil)
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagUserRemove, domain.AuditStatusSuccess, testFlagUUID, changes)).Return(nil)
		w, req := newFeatureFlagsRequest("DELETE", "/feature-flags/"+testFlagUUID+"/users/"+testFlagUserUUID, nil, pathValues)

		controller.RemoveFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("error - invalid user uuid", func(t *testing.T) {
		controller, serviceMock, _, _, _ := newTestFeatureFlagsController()
		w, req := newFeatureFlagsRequest("DELETE", "/feature-flags/"+testFlagUUID+"/users/nope", nil, map[string]string{"uuid": testFlagUUID, "userUuid": "nope"})

		controller.RemoveFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		serviceMock.AssertNotCalled(t, "RemoveUser", mock.Anything, mock.Anything)
	})

	t.Run("error - user not in the allow-list is audited as a failure", func(t *testing.T) {
		controller, serviceMock, auditMock, _, _ := newTestFeatureFlagsController()
		serviceMock.On("RemoveUser", testFlagUUID, testFlagUserUUID).Return(domain.NewNotFoundError("featureFlags.users.notFound"))
		auditMock.On("Log", matchFeatureFlagAudit(domain.AuditActionFeatureFlagUserRemove, domain.AuditStatusFailure, testFlagUUID, changes)).Return(nil)
		w, req := newFeatureFlagsRequest("DELETE", "/feature-flags/"+testFlagUUID+"/users/"+testFlagUserUUID, nil, pathValues)

		controller.RemoveFeatureFlagUser(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		auditMock.AssertExpectations(t)
	})
}
