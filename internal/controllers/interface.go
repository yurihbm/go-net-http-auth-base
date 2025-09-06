package controllers

import "net/http"

type Controller interface {
	RegisterRoutes(router *http.ServeMux)
}
