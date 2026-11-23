package shared

import (
	"net"
	"net/http"

	"go-net-http-auth-base/internal/domain"
)

type ContextKey string

const RequestContextDataKey ContextKey = "requestContextData"

type RequestContextData struct {
	UserUUID    string
	UserRole    domain.UserRole
	SessionUUID string
	RequestUUID string
	ClientIP    string
	Error       error
}

// ClientIP returns the client IP resolved by the client IP middleware, or the
// RemoteAddr host when none was resolved.
func ClientIP(r *http.Request) string {
	if data, ok := r.Context().Value(RequestContextDataKey).(*RequestContextData); ok && data.ClientIP != "" {
		return data.ClientIP
	}
	return RemoteHost(r.RemoteAddr)
}

func RemoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
