package repositories

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"
)

type AuditPostgresRepository struct {
	q *postgres.Queries
}

func NewAuditPostgresRepository(db postgres.DBTX) domain.AuditRepository {
	return &AuditPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *AuditPostgresRepository) Create(log *domain.AuditLog) error {
	var changesBytes []byte
	if log.Changes != nil {
		var err error
		changesBytes, err = json.Marshal(log.Changes)
		if err != nil {
			return err
		}
	}

	var actorUUID pgtype.UUID
	if log.ActorUUID != nil {
		if err := actorUUID.Scan(*log.ActorUUID); err != nil {
			return err
		}
	}

	var requestUUID pgtype.UUID
	if err := requestUUID.Scan(log.RequestUUID); err != nil {
		return err
	}

	var failureReason pgtype.Text
	if log.FailureReason != nil {
		if err := failureReason.Scan(*log.FailureReason); err != nil {
			return err
		}
	}

	params := postgres.CreateAuditLogParams{
		ActorUuid:     actorUUID,
		IpAddress:     log.IPAddress,
		UserAgent:     log.UserAgent,
		Action:        log.Action,
		ResourceType:  log.ResourceType,
		ResourceUuid:  log.ResourceUUID,
		RequestUuid:   requestUUID,
		Changes:       changesBytes,
		Status:        log.Status,
		FailureReason: failureReason,
	}

	return r.q.CreateAuditLog(context.Background(), params)
}
