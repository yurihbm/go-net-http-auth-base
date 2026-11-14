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

// @Summary		List audit logs
// @Description	Lists audit logs with cursor pagination. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			audit-logs
// @Produce		json
// @Param			action			query		string								false	"Filter by action"
// @Param			resource_type	query		string								false	"Filter by resource type"
// @Param			status			query		string								false	"Filter by status"
// @Param			actor_uuid		query		string								false	"Filter by actor UUID"
// @Param			cursor			query		string								false	"Cursor from meta.next_cursor"
// @Param			limit			query		int									false	"Page size"				minimum(1)	maximum(100)	default(20)
// @Param			start_date		query		string								false	"Start date (RFC3339)"	format(date-time)
// @Param			end_date		query		string								false	"End date (RFC3339)"	format(date-time)
// @Success		200				{object}	api.ResponseBody[[]domain.AuditLog]	"Audit log page"
// @Failure		400				{object}	api.ResponseBody[any]				"Validation error"
// @Failure		401				{object}	api.ResponseBody[any]				"Unauthorized"
// @Failure		403				{object}	api.ResponseBody[any]				"Forbidden"
// @Failure		500				{object}	api.ResponseBody[any]				"Internal server error"
// @Router			/audit-logs [get]
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
