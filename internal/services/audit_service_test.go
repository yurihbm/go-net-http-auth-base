package services_test

import (
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

		err := service.Log(dto)

		assert.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		auditRepositoryMock := new(mocks.AuditRepositoryMock)
		auditRepositoryMock.On("Create", mock.Anything).Return(assert.AnError)

		service := services.NewAuditService(auditRepositoryMock)

		err := service.Log(dto)

		assert.Error(t, err)
	})
}
