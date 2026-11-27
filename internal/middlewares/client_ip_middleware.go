package middlewares

import (
	"net/http"
	"net/netip"
	"strings"

	"go-net-http-auth-base/internal/shared"
)

const maxForwardedHops = 32

type ClientIPMiddleware struct {
	trusted []netip.Prefix
}

func NewClientIPMiddleware(trusted []netip.Prefix) GlobalMiddleware {
	return &ClientIPMiddleware{trusted: trusted}
}

func (m *ClientIPMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, ok := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData); ok {
			data.ClientIP = m.resolve(r)
		}

		next.ServeHTTP(w, r)
	})
}

func (m *ClientIPMiddleware) resolve(r *http.Request) string {
	remote := shared.RemoteHost(r.RemoteAddr)
	remoteAddr, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	remoteAddr = remoteAddr.Unmap()
	client := remoteAddr.String()
	if !m.isTrusted(remoteAddr) {
		return client
	}

	// Walk X-Forwarded-For right to left: each trusted proxy appends the
	// address it received from, so entries left of the first untrusted one
	// are client-controlled. An invalid entry ends the walk at the last
	// trusted hop seen. The walk peels entries off the end without
	// collecting them and stops after maxForwardedHops, so a huge
	// client-supplied header costs nothing.
	values := r.Header.Values("X-Forwarded-For")
	current := ""
	for range maxForwardedHops {
		for current == "" && len(values) > 0 {
			current = values[len(values)-1]
			values = values[:len(values)-1]
		}
		if current == "" {
			return client
		}

		entry := current
		if i := strings.LastIndexByte(current, ','); i >= 0 {
			entry = current[i+1:]
			current = current[:i]
		} else {
			current = ""
		}

		addr, err := netip.ParseAddr(strings.TrimSpace(entry))
		if err != nil {
			return client
		}
		addr = addr.Unmap()
		client = addr.String()
		if !m.isTrusted(addr) {
			return client
		}
	}

	return client
}

func (m *ClientIPMiddleware) isTrusted(addr netip.Addr) bool {
	for _, prefix := range m.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
