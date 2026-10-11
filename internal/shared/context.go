package shared

import "go-net-http-auth-base/internal/domain"

type ContextKey string

const RequestContextDataKey ContextKey = "requestContextData"

type RequestContextData struct {
	UserUUID    string
	UserRole    domain.UserRole
	RequestUUID string
	Error       error
}
