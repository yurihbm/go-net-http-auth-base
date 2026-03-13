package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type AuditRepositoryMock struct {
	mock.Mock
}

var _ domain.AuditRepository = (*AuditRepositoryMock)(nil)

func (m *AuditRepositoryMock) Create(ctx context.Context, log *domain.AuditLog) error {
	args := m.Called(log)
	if args.Get(0) != nil {
		return args.Error(0)
	}
	return nil
}

func (m *AuditRepositoryMock) List(ctx context.Context, dto domain.ListAuditLogsDTO) ([]domain.AuditLog, int64, error) {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Get(0).([]domain.AuditLog), args.Get(1).(int64), args.Error(2)
	}
	return nil, args.Get(1).(int64), args.Error(2)
}
