package controllers

import (
	"net/http"
	"strconv"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
)

const defaultAuditLogLimit = 20

type AuditController struct {
	auditService   domain.AuditService
	authMiddleware middlewares.HandlerMiddleware
	roleMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*AuditController)(nil)

func NewAuditController(
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
	roleMiddleware middlewares.HandlerMiddleware,
) *AuditController {
	return &AuditController{
		auditService:   auditService,
		authMiddleware: authMiddleware,
		roleMiddleware: roleMiddleware,
	}
}

func (c *AuditController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("GET /audit-logs", c.authMiddleware.Use(c.roleMiddleware.Use(c.ListAuditLogs)))
}

func (c *AuditController) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	dto := domain.ListAuditLogsDTO{
		Limit: defaultAuditLogLimit,
	}

	if v := q.Get("action"); v != "" {
		dto.Action = &v
	}
	if v := q.Get("resource_type"); v != "" {
		dto.ResourceType = &v
	}
	if v := q.Get("status"); v != "" {
		dto.Status = &v
	}
	if v := q.Get("actor_uuid"); v != "" {
		dto.ActorUUID = &v
	}
	if v := q.Get("cursor"); v != "" {
		dto.Cursor = &v
	}

	if v := q.Get("limit"); v != "" {
		limit, err := strconv.Atoi(v)
		if err != nil || limit < 1 || limit > 100 {
			api.HandleError(r.Context(), w,
				domain.NewValidationError("audit.list.badRequest",
					map[string]string{
						"limit": "limit must be an integer between 1 and 100",
					},
				),
			)
			return
		}
		dto.Limit = limit
	}

	if v := q.Get("start_date"); v != "" {
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			api.HandleError(r.Context(), w,
				domain.NewValidationError("audit.list.badRequest",
					map[string]string{
						"start_date": "start_date must be a valid ISO 8601 string (e.g. 2024-06-07T14:25:13Z)",
					},
				),
			)
			return
		}
		unixTime := parsed.UTC().Unix()
		dto.StartDate = &unixTime
	}

	if v := q.Get("end_date"); v != "" {
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			api.HandleError(r.Context(), w,
				domain.NewValidationError("audit.list.badRequest",
					map[string]string{
						"end_date": "end_date must be a valid ISO 8601 string (e.g. 2024-06-07T14:25:13Z)",
					},
				),
			)
			return
		}
		unixTime := parsed.UTC().Unix()
		dto.EndDate = &unixTime
	}

	page, err := c.auditService.List(r.Context(), dto)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[[]domain.AuditLog]{
		Data:    page.Items,
		Message: "audit.list.success",
		Meta: &api.ResponseMeta{
			Total:      page.Total,
			Limit:      dto.Limit,
			NextCursor: page.NextCursor,
		},
	})
}
