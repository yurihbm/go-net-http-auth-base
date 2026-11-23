package middlewares

import (
	"net/http"
	"net/netip"
	"strings"

	"go-net-http-auth-base/internal/shared"
)

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
	if err != nil || !m.isTrusted(remoteAddr.Unmap()) {
		return remote
	}

	// Walk X-Forwarded-For right to left: each trusted proxy appends the
	// address it received from, so entries left of the first untrusted one
	// are client-controlled. An invalid entry ends the walk at the last
	// trusted hop seen.
	client := remoteAddr.Unmap().String()
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		for hop := range strings.SplitSeq(value, ",") {
			hops = append(hops, strings.TrimSpace(hop))
		}
	}

	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
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
