package mocks

import (
	"net/http"

	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/mock"
)

type AuthMiddlewareMock struct {
	mock.Mock
}

var _ middlewares.HandlerMiddleware = (*AuthMiddlewareMock)(nil)

func (m *AuthMiddlewareMock) Use(next http.HandlerFunc) http.HandlerFunc {
	m.Called(next)
	return next
}
