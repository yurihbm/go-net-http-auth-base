package controllers

import (
	"context"
	"go-net-http-auth-base/internal/api"
	"net/http"
	"time"
)

type Pinger interface {
	Ping(ctx context.Context) error
}

type HealthController struct {
	db Pinger
}

func NewHealthController(db Pinger) *HealthController {
	return &HealthController{
		db: db,
	}
}

func (c *HealthController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("GET /health", c.Health)
	router.HandleFunc("GET /ready", c.Ready)
}

func (c *HealthController) Health(w http.ResponseWriter, r *http.Request) {
	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[string]{
		Data: "OK",
	})
}

func (c *HealthController) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := c.db.Ping(ctx); err != nil {
		api.WriteJSONResponse(w, http.StatusServiceUnavailable, api.ResponseBody[string]{
			Error: "Database not ready",
		})
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[string]{
		Data: "OK",
	})
}
