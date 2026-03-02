package services

import "go-net-http-auth-base/internal/domain"

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

func (s *auditService) Log(dto domain.CreateAuditLogDTO) error {
	err := s.auditRepository.Create(&domain.AuditLog{
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

	return err
}
