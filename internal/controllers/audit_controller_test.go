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
	"github.com/stretchr/testify/mock"
)

func newTestAuditController() (*controllers.AuditController, *mocks.AuditServiceMock, *mocks.AuthMiddlewareMock, *mocks.AuthMiddlewareMock) {
	auditMock := new(mocks.AuditServiceMock)
	authMiddlewareMock := new(mocks.AuthMiddlewareMock)
	roleMiddlewareMock := new(mocks.AuthMiddlewareMock)
	controller := controllers.NewAuditController(auditMock, authMiddlewareMock, roleMiddlewareMock)
	return controller, auditMock, authMiddlewareMock, roleMiddlewareMock
}

func TestAuditController_RegisterRoutes(t *testing.T) {
	t.Run("should register routes with auth and role middlewares", func(t *testing.T) {
		router := http.NewServeMux()
		controller, _, authMiddleware, roleMiddleware := newTestAuditController()
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(1)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything).Times(1)

		controller.RegisterRoutes(router)

		authMiddleware.AssertNumberOfCalls(t, "Use", 1)
		roleMiddleware.AssertNumberOfCalls(t, "Use", 1)
	})
}

func TestAuditController_ListAuditLogs(t *testing.T) {
	actorUUID := "actor-uuid-1"
	items := []domain.AuditLog{
		{
			UUID:         "019623b0-0000-7000-8000-000000000001",
			Action:       domain.AuditActionUserCreate,
			ResourceType: domain.AuditResourceUser,
			ResourceUUID: "resource-uuid-1",
			ActorUUID:    &actorUUID,
			Status:       domain.AuditStatusSuccess,
			IPAddress:    "127.0.0.1",
			UserAgent:    "test-agent",
			RequestUUID:  "req-uuid-1",
			CreatedAt:    "2023-11-15T12:00:00Z",
		},
	}
	nextCursor := "019623b0-0000-7000-8000-000000000001"

	t.Run("success with defaults", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		page := &domain.AuditLogPage{
			Items:      items,
			NextCursor: &nextCursor,
			Total:      1,
		}

		auditMock.On("List", mock.MatchedBy(func(dto domain.ListAuditLogsDTO) bool {
			return dto.Limit == 20 &&
				dto.Action == nil &&
				dto.ResourceType == nil &&
				dto.Status == nil &&
				dto.ActorUUID == nil &&
				dto.Cursor == nil &&
				dto.StartDate == nil &&
				dto.EndDate == nil
		})).Return(page, nil)

		w, req := getControllerArgs("GET", "/audit-logs", nil)

		controller.ListAuditLogs(w, req)

		var response api.ResponseBody[[]domain.AuditLog]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, items, response.Data)
		assert.Equal(t, "audit.list.success", response.Message)
		assert.NotNil(t, response.Meta)
		assert.Equal(t, int64(1), response.Meta.Total)
		assert.Equal(t, 20, response.Meta.Limit)
		assert.Equal(t, &nextCursor, response.Meta.NextCursor)
		auditMock.AssertExpectations(t)
	})

	t.Run("success with all filters", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		action := domain.AuditActionLogin
		resourceType := domain.AuditResourceAuth
		status := domain.AuditStatusSuccess
		actor := "actor-uuid-abc"
		cursor := "019623b0-0000-7000-8000-000000000002"

		// Nov 15, 2023 00:00:00 UTC → Nov 16, 2023 00:00:00 UTC (24-hour window)
		startTime := time.Date(2023, time.November, 15, 0, 0, 0, 0, time.UTC)
		endTime := time.Date(2023, time.November, 16, 0, 0, 0, 0, time.UTC)
		startDate := startTime.Unix()
		endDate := endTime.Unix()

		page := &domain.AuditLogPage{Items: items, Total: 1}

		auditMock.On("List", mock.MatchedBy(func(dto domain.ListAuditLogsDTO) bool {
			return dto.Limit == 10 &&
				dto.Action != nil && *dto.Action == action &&
				dto.ResourceType != nil && *dto.ResourceType == resourceType &&
				dto.Status != nil && *dto.Status == status &&
				dto.ActorUUID != nil && *dto.ActorUUID == actor &&
				dto.Cursor != nil && *dto.Cursor == cursor &&
				dto.StartDate != nil && *dto.StartDate == startDate &&
				dto.EndDate != nil && *dto.EndDate == endDate
		})).Return(page, nil)

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("action", action)
		q.Set("resource_type", resourceType)
		q.Set("status", status)
		q.Set("actor_uuid", actor)
		q.Set("cursor", cursor)
		q.Set("limit", "10")
		q.Set("start_date", startTime.Format(time.RFC3339))
		q.Set("end_date", endTime.Format(time.RFC3339))
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("invalid limit - not a number", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("limit", "abc")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid limit - out of range (0)", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("limit", "0")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid limit - out of range (101)", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("limit", "101")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid start_date - garbage string", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("start_date", "not-a-timestamp")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid start_date - unix integer string", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("start_date", "1699920000")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid start_date - date only without time or timezone", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("start_date", "2024-06-07")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("valid start_date - +00:00 offset accepted and normalized to same unix as Z", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		refTime := time.Date(2024, time.June, 7, 14, 25, 13, 0, time.UTC)
		expectedUnix := refTime.Unix()

		page := &domain.AuditLogPage{Items: []domain.AuditLog{}, Total: 0}
		auditMock.On("List", mock.MatchedBy(func(dto domain.ListAuditLogsDTO) bool {
			return dto.StartDate != nil && *dto.StartDate == expectedUnix
		})).Return(page, nil)

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("start_date", "2024-06-07T14:25:13+00:00")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("valid start_date - non-UTC offset normalized to UTC unix", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		// 2024-06-07T17:25:13+03:00 is the same instant as 2024-06-07T14:25:13Z
		refTime := time.Date(2024, time.June, 7, 14, 25, 13, 0, time.UTC)
		expectedUnix := refTime.Unix()

		page := &domain.AuditLogPage{Items: []domain.AuditLog{}, Total: 0}
		auditMock.On("List", mock.MatchedBy(func(dto domain.ListAuditLogsDTO) bool {
			return dto.StartDate != nil && *dto.StartDate == expectedUnix
		})).Return(page, nil)

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("start_date", "2024-06-07T17:25:13+03:00")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("invalid end_date - garbage string", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("end_date", "not-a-timestamp")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid end_date - unix integer string", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("end_date", "1700006400")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("invalid end_date - date only without time or timezone", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		w, req := getControllerArgs("GET", "/audit-logs", nil)
		q := req.URL.Query()
		q.Set("end_date", "2024-06-08")
		req.URL.RawQuery = q.Encode()

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		auditMock.AssertNotCalled(t, "List")
	})

	t.Run("service error", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		auditMock.On("List", mock.Anything).Return(nil, assert.AnError)

		w, req := getControllerArgs("GET", "/audit-logs", nil)

		controller.ListAuditLogs(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		auditMock.AssertExpectations(t)
	})

	t.Run("empty result", func(t *testing.T) {
		controller, auditMock, _, _ := newTestAuditController()

		page := &domain.AuditLogPage{
			Items: []domain.AuditLog{},
			Total: 0,
		}

		auditMock.On("List", mock.Anything).Return(page, nil)

		w, req := getControllerArgs("GET", "/audit-logs", nil)

		controller.ListAuditLogs(w, req)

		var response api.ResponseBody[[]domain.AuditLog]
		err := json.Unmarshal(w.Body.Bytes(), &response)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, response.Data)
		assert.NotNil(t, response.Meta)
		assert.Equal(t, int64(0), response.Meta.Total)
		assert.Nil(t, response.Meta.NextCursor)
		auditMock.AssertExpectations(t)
	})
}
