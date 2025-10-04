package middlewares

import "net/http"

type Middleware interface {
	Use(next http.HandlerFunc) http.HandlerFunc
}
