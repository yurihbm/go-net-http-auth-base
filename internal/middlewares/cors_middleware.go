package middlewares

import (
	"net/http"
	"slices"
	"strings"
)

type CORSMiddleware struct {
	allowedOrigins   []string
	allowedMethods   []string
	allowedHeaders   []string
	exposeHeaders    []string
	allowCredentials bool
	maxAge           string
}

var _ GlobalMiddleware = (*CORSMiddleware)(nil)

func NewCORSMiddleware(
	allowedOrigins []string,
	allowedMethods []string,
	allowedHeaders []string,
	exposeHeaders []string,
	allowCredentials bool,
	maxAge string,
) GlobalMiddleware {
	if maxAge == "" {
		maxAge = "86400"
	}

	return &CORSMiddleware{
		allowedOrigins:   allowedOrigins,
		allowedMethods:   allowedMethods,
		allowedHeaders:   allowedHeaders,
		exposeHeaders:    exposeHeaders,
		allowCredentials: allowCredentials,
		maxAge:           maxAge,
	}
}

func (m *CORSMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Vary", "Origin")

		allowedOrigin := m.getAllowedOrigin(origin)
		if origin != "" && allowedOrigin == nil && r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if allowedOrigin != nil {
			w.Header().Set("Access-Control-Allow-Origin", *allowedOrigin)
		}

		if len(m.allowedMethods) > 0 {
			w.Header().Set(
				"Access-Control-Allow-Methods",
				strings.Join(m.allowedMethods, ", "),
			)
		}
		if len(m.allowedHeaders) > 0 {
			w.Header().Set(
				"Access-Control-Allow-Headers",
				strings.Join(m.allowedHeaders, ", "),
			)
		}
		if len(m.exposeHeaders) > 0 {
			w.Header().Set(
				"Access-Control-Expose-Headers",
				strings.Join(m.exposeHeaders, ", "),
			)
		}
		if m.allowCredentials && allowedOrigin != nil && *allowedOrigin != "*" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Max-Age", m.maxAge)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *CORSMiddleware) getAllowedOrigin(origin string) *string {
	if slices.Contains(m.allowedOrigins, origin) {
		return &origin
	}

	if slices.Contains(m.allowedOrigins, "*") {
		wildcard := "*"
		return &wildcard
	}

	return nil
}
