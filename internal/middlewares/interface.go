package middlewares

import "net/http"

type HandlerMiddleware interface {
	Use(next http.HandlerFunc) http.HandlerFunc
}

type GlobalMiddleware interface {
	Use(next http.Handler) http.Handler
}
