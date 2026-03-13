package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type AuditServiceMock struct {
	mock.Mock
}

var _ domain.AuditService = (*AuditServiceMock)(nil)

func (m *AuditServiceMock) Log(ctx context.Context, dto domain.CreateAuditLogDTO) error {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Error(0)
	}
	return nil
}

func (m *AuditServiceMock) List(ctx context.Context, dto domain.ListAuditLogsDTO) (*domain.AuditLogPage, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).(*domain.AuditLogPage), args.Error(1)
	}
	return nil, args.Error(1)
}
