package controllers

import (
	_ "embed"
	"net/http"

	_ "go-net-http-auth-base/docs/swagger"
	"go-net-http-auth-base/internal/middlewares"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

//go:embed assets/swagger_login.html
var swaggerLoginPage []byte

//go:embed assets/swagger_ui_logout.js
var swaggerLogoutScript string

//go:embed assets/swagger_ui_response_interceptor.js
var swaggerResponseInterceptor string

type DocsController struct {
	authMiddleware middlewares.HandlerMiddleware
	roleMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*DocsController)(nil)

func NewDocsController(
	authMiddleware middlewares.HandlerMiddleware,
	roleMiddleware middlewares.HandlerMiddleware,
) *DocsController {
	return &DocsController{
		authMiddleware: authMiddleware,
		roleMiddleware: roleMiddleware,
	}
}

func (c *DocsController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("GET /swagger/{$}", c.LoginGate)
	router.HandleFunc("GET /swagger/", c.authMiddleware.Use(c.roleMiddleware.Use(c.swaggerUI())))
}

func (c *DocsController) LoginGate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Write(swaggerLoginPage)
}

func (c *DocsController) swaggerUI() http.HandlerFunc {
	return httpSwagger.Handler(
		httpSwagger.AfterScript(swaggerLogoutScript),
		httpSwagger.UIConfig(map[string]string{"responseInterceptor": swaggerResponseInterceptor}),
	)
}
