package middlewares

import "net/http"

type SecurityHeadersMiddleware struct {
	secure bool
}

func NewSecurityHeadersMiddleware(secure bool) GlobalMiddleware {
	return &SecurityHeadersMiddleware{secure: secure}
}

func (m *SecurityHeadersMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if m.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
