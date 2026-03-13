package controllers

import (
	"log/slog"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
)

// auditLog fires an audit log entry and silently swallows persistence errors so
// they never affect the HTTP response status returned to the client.
func auditLog(r *http.Request, auditService domain.AuditService, dto domain.CreateAuditLogDTO) {
	reqCtxData, _ := r.Context().Value(api.RequestContextDataKey).(*api.RequestContextData)
	if reqCtxData != nil && reqCtxData.RequestUUID != "" {
		dto.RequestUUID = reqCtxData.RequestUUID
	}

	ip, ua := api.GetClientMetadata(r)
	dto.IPAddress = ip
	dto.UserAgent = ua

	if err := auditService.Log(r.Context(), dto); err != nil {
		slog.Error("audit log failed", "error", err, "action", dto.Action)
	}
}

// actorUUID returns a pointer to the authenticated user UUID from context, or
// nil when the request is unauthenticated.
func actorUUID(r *http.Request) *string {
	reqCtxData, _ := r.Context().Value(api.RequestContextDataKey).(*api.RequestContextData)
	if reqCtxData != nil && reqCtxData.UserUUID != "" {
		u := reqCtxData.UserUUID
		return &u
	}
	return nil
}
