package mocks

import (
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type AuditRepositoryMock struct {
	mock.Mock
}

var _ domain.AuditRepository = (*AuditRepositoryMock)(nil)

func (m *AuditRepositoryMock) Create(log *domain.AuditLog) error {
	args := m.Called(log)
	if args.Get(0) != nil {
		return args.Error(0)
	}
	return nil
}
