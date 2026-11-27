package services

import (
	"context"

	"go-net-http-auth-base/internal/domain"
)

type auditService struct {
	auditRepository domain.AuditRepository
}

func NewAuditService(
	auditRepository domain.AuditRepository,
) domain.AuditService {
	return &auditService{
		auditRepository,
	}
}

func (s *auditService) Log(ctx context.Context, dto domain.CreateAuditLogDTO) error {
	return s.auditRepository.Create(ctx, &domain.AuditLog{
		ActorUUID:     dto.ActorUUID,
		IPAddress:     dto.IPAddress,
		UserAgent:     dto.UserAgent,
		Action:        dto.Action,
		ResourceType:  dto.ResourceType,
		ResourceUUID:  dto.ResourceUUID,
		RequestUUID:   dto.RequestUUID,
		Changes:       dto.Changes,
		Status:        dto.Status,
		FailureReason: dto.FailureReason,
	})
}

func (s *auditService) List(ctx context.Context, dto domain.ListAuditLogsDTO) (*domain.Page[domain.AuditLog], error) {
	limit := dto.Limit
	dto.Limit++
	logs, total, err := s.auditRepository.List(ctx, dto)
	if err != nil {
		return nil, err
	}

	return domain.NewPage(logs, total, limit, func(l domain.AuditLog) string { return l.UUID }), nil
}
