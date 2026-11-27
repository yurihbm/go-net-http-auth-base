package services_test

import (
	"context"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewAuditService(t *testing.T) {
	auditRepositoryMock := new(mocks.AuditRepositoryMock)
	service := services.NewAuditService(auditRepositoryMock)
	assert.NotNil(t, service)
}

func TestAuthService_Log(t *testing.T) {
	dto := domain.CreateAuditLogDTO{
		IPAddress:    "1.1.1.1",
		UserAgent:    "Mozilla/5.0",
		Action:       "LOGIN",
		ResourceType: "auth",
		ResourceUUID: "123",
		RequestUUID:  "req-123",
		Status:       "SUCCESS",
	}

	t.Run("success", func(t *testing.T) {
		auditRepositoryMock := new(mocks.AuditRepositoryMock)
		auditRepositoryMock.On("Create", mock.Anything).Return(nil)

		service := services.NewAuditService(auditRepositoryMock)

		err := service.Log(context.Background(), dto)

		assert.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		auditRepositoryMock := new(mocks.AuditRepositoryMock)
		auditRepositoryMock.On("Create", mock.Anything).Return(assert.AnError)

		service := services.NewAuditService(auditRepositoryMock)

		err := service.Log(context.Background(), dto)

		assert.Error(t, err)
	})
}

func TestAuditService_List(t *testing.T) {
	makeLog := func(id string) domain.AuditLog {
		return domain.AuditLog{UUID: id, Action: "LOGIN", Status: "SUCCESS"}
	}

	dto := domain.ListAuditLogsDTO{Limit: 2}
	probeDTO := domain.ListAuditLogsDTO{Limit: 3}

	t.Run("success - no results, NextCursor is nil", func(t *testing.T) {
		repo := new(mocks.AuditRepositoryMock)
		repo.On("List", probeDTO).Return([]domain.AuditLog{}, int64(0), nil)

		service := services.NewAuditService(repo)
		page, err := service.List(context.Background(), dto)

		assert.NoError(t, err)
		assert.Empty(t, page.Items)
		assert.Nil(t, page.NextCursor)
		assert.Equal(t, int64(0), page.Total)
		repo.AssertExpectations(t)
	})

	t.Run("success - more rows than limit, items trimmed and NextCursor is last kept UUID", func(t *testing.T) {
		logs := []domain.AuditLog{makeLog("uuid-1"), makeLog("uuid-2"), makeLog("uuid-3")}
		repo := new(mocks.AuditRepositoryMock)
		repo.On("List", probeDTO).Return(logs, int64(10), nil)

		service := services.NewAuditService(repo)
		page, err := service.List(context.Background(), dto)

		assert.NoError(t, err)
		require.Len(t, page.Items, 2)
		assert.Equal(t, "uuid-2", page.Items[1].UUID)
		require.NotNil(t, page.NextCursor)
		assert.Equal(t, "uuid-2", *page.NextCursor)
		assert.Equal(t, int64(10), page.Total)
		repo.AssertExpectations(t)
	})

	t.Run("success - exactly limit rows left, NextCursor is nil even when total is larger", func(t *testing.T) {
		logs := []domain.AuditLog{makeLog("uuid-1"), makeLog("uuid-2")}
		repo := new(mocks.AuditRepositoryMock)
		repo.On("List", probeDTO).Return(logs, int64(10), nil)

		service := services.NewAuditService(repo)
		page, err := service.List(context.Background(), dto)

		assert.NoError(t, err)
		assert.Len(t, page.Items, 2)
		assert.Nil(t, page.NextCursor)
		assert.Equal(t, int64(10), page.Total)
		repo.AssertExpectations(t)
	})

	t.Run("repository error is propagated", func(t *testing.T) {
		repo := new(mocks.AuditRepositoryMock)
		repo.On("List", probeDTO).Return(nil, int64(0), assert.AnError)

		service := services.NewAuditService(repo)
		page, err := service.List(context.Background(), dto)

		assert.Nil(t, page)
		assert.Error(t, err)
		repo.AssertExpectations(t)
	})
}
