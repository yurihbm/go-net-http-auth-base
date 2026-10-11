package mocks

import (
	"context"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/mock"
)

type TransactorMock struct {
	mock.Mock
}

var _ domain.Transactor = (*TransactorMock)(nil)

func (m *TransactorMock) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	m.Called()
	return fn(ctx)
}
