package api

import (
	"net"
	"net/http"
	"strings"
)

// GetClientMetadata extracts the client IP address and User-Agent from the
// request. IP resolution follows the priority order:
//  1. X-Forwarded-For header (first address in the list)
//  2. X-Real-IP header
//  3. r.RemoteAddr (port stripped)
func GetClientMetadata(r *http.Request) (ip string, userAgent string) {
	userAgent = r.Header.Get("User-Agent")

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip = strings.TrimSpace(parts[0])
		return
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip = strings.TrimSpace(xri)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		return
	}
	ip = host
	return
}
