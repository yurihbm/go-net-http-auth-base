package repositories

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
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

func (r *AuditPostgresRepository) Create(ctx context.Context, log *domain.AuditLog) error {
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

	return r.q.CreateAuditLog(ctx, params)
}

func (r *AuditPostgresRepository) List(ctx context.Context, dto domain.ListAuditLogsDTO) ([]domain.AuditLog, int64, error) {
	limit := int64(dto.Limit)

	var action, resourceType, status pgtype.Text
	if dto.Action != nil {
		action = pgtype.Text{String: *dto.Action, Valid: true}
	}
	if dto.ResourceType != nil {
		resourceType = pgtype.Text{String: *dto.ResourceType, Valid: true}
	}
	if dto.Status != nil {
		status = pgtype.Text{String: *dto.Status, Valid: true}
	}

	var actorUUID pgtype.UUID
	if dto.ActorUUID != nil {
		parsed, err := parseAuditActorUUID(*dto.ActorUUID)
		if err != nil {
			return nil, 0, err
		}
		actorUUID = *parsed
	}

	var cursor pgtype.UUID
	if dto.Cursor != nil {
		parsed, err := parseAuditCursorUUID(*dto.Cursor)
		if err != nil {
			return nil, 0, err
		}
		cursor = *parsed
	}

	var startDate, endDate pgtype.Timestamptz
	if dto.StartDate != nil {
		startDate = pgtype.Timestamptz{Time: time.Unix(*dto.StartDate, 0).UTC(), Valid: true}
	}
	if dto.EndDate != nil {
		endDate = pgtype.Timestamptz{Time: time.Unix(*dto.EndDate, 0).UTC(), Valid: true}
	}

	countParams := postgres.CountAuditLogsParams{
		StartDate:    startDate,
		EndDate:      endDate,
		Action:       action,
		ResourceType: resourceType,
		Status:       status,
		ActorUuid:    actorUUID,
	}

	total, err := r.q.CountAuditLogs(ctx, countParams)
	if err != nil {
		return nil, 0, domain.NewInternalServerError("auditLogs.internalServerError", err)
	}

	listParams := postgres.ListAuditLogsParams{
		StartDate:    startDate,
		EndDate:      endDate,
		Action:       action,
		ResourceType: resourceType,
		Status:       status,
		ActorUuid:    actorUUID,
		Cursor:       cursor,
		PageSize:     limit,
	}

	rows, err := r.q.ListAuditLogs(ctx, listParams)
	if err != nil {
		return nil, 0, domain.NewInternalServerError("auditLogs.internalServerError", err)
	}

	logs := make([]domain.AuditLog, 0, len(rows))
	for _, row := range rows {
		logs = append(logs, toDomainAuditLog(row))
	}

	return logs, total, nil
}

func toDomainAuditLog(row postgres.AuditLog) domain.AuditLog {
	uuidBytes := row.Uuid.Bytes
	logUUID := uuid.UUID(uuidBytes).String()

	var actorUUID *string
	if row.ActorUuid.Valid {
		actorUUIDBytes := row.ActorUuid.Bytes
		s := uuid.UUID(actorUUIDBytes).String()
		actorUUID = &s
	}

	requestUUIDBytes := row.RequestUuid.Bytes
	requestUUID := uuid.UUID(requestUUIDBytes).String()

	var failureReason *string
	if row.FailureReason.Valid {
		failureReason = &row.FailureReason.String
	}

	var changes any
	if row.Changes != nil {
		if err := json.Unmarshal(row.Changes, &changes); err != nil {
			slog.Warn("failed to unmarshal audit log changes", "error", err, "uuid", uuid.UUID(row.Uuid.Bytes).String())
		}
	}

	return domain.AuditLog{
		UUID:          logUUID,
		ActorUUID:     actorUUID,
		IPAddress:     row.IpAddress,
		UserAgent:     row.UserAgent,
		Action:        row.Action,
		ResourceType:  row.ResourceType,
		ResourceUUID:  row.ResourceUuid,
		RequestUUID:   requestUUID,
		Changes:       changes,
		Status:        row.Status,
		FailureReason: failureReason,
		CreatedAt:     row.CreatedAt.Time.UTC().Format(time.RFC3339),
	}
}

func parseAuditActorUUID(uuidStr string) (*pgtype.UUID, error) {
	return parseUUID(uuidStr, "auditLogs.invalidActorUUID")
}

func parseAuditCursorUUID(uuidStr string) (*pgtype.UUID, error) {
	return parseUUID(uuidStr, "auditLogs.invalidCursor")
}
