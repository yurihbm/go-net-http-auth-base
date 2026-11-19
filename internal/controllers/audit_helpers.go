package controllers

import (
	"log/slog"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
)

// auditLog fires an audit log entry and silently swallows persistence errors so
// they never affect the HTTP response status returned to the client.
func auditLog(r *http.Request, auditService domain.AuditService, dto domain.CreateAuditLogDTO) {
	reqCtxData, _ := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData)
	if reqCtxData != nil && reqCtxData.RequestUUID != "" {
		dto.RequestUUID = reqCtxData.RequestUUID
	}

	ip, ua := api.GetClientMetadata(r)
	dto.IPAddress = ip
	dto.UserAgent = ua

	if err := auditService.Log(r.Context(), dto); err != nil {
		slog.ErrorContext(r.Context(), "audit log failed", "error", err, "action", dto.Action)
	}
}

func auditResult(r *http.Request, auditService domain.AuditService, dto domain.CreateAuditLogDTO, err error) {
	dto.Status = domain.AuditStatusSuccess
	if err != nil {
		reason := err.Error()
		dto.Status = domain.AuditStatusFailure
		dto.FailureReason = &reason
	}
	auditLog(r, auditService, dto)
}
