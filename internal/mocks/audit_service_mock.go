package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type AuditServiceMock struct {
	mock.Mock
}

var _ domain.AuditService = (*AuditServiceMock)(nil)

func (m *AuditServiceMock) Log(dto domain.CreateAuditLogDTO) error {
	args := m.Called(dto)
	if args.Get(0) != nil {
		return args.Error(0)
	}
	return nil
}
