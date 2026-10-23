package repositories

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type SessionsPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.SessionsRepository = (*SessionsPostgresRepository)(nil)

func NewSessionsPostgresRepository(db postgres.DBTX) domain.SessionsRepository {
	return &SessionsPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *SessionsPostgresRepository) Create(ctx context.Context, session domain.UserSession) (*domain.UserSession, error) {
	userUUID, err := parseUsersUUID(session.UserUUID)
	if err != nil {
		return nil, err
	}

	created, err := r.q.CreateUserSession(ctx, postgres.CreateUserSessionParams{
		UserUuid:   *userUUID,
		CurrentJti: session.CurrentJTI,
		ExpiresAt:  pgtype.Timestamptz{Time: time.Unix(session.ExpiresAt, 0), Valid: true},
	})
	if err != nil {
		if fkErr := isForeignKeyViolationError(err, "users.notFound"); fkErr != nil {
			return nil, fkErr
		}
		return nil, domain.NewInternalServerError("sessions.internalServerError", err)
	}

	domainSession := toDomainUserSession(created)
	return &domainSession, nil
}

func (r *SessionsPostgresRepository) FindByUUID(ctx context.Context, userUUIDStr string, sessionUUIDStr string) (*domain.UserSession, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return nil, err
	}

	session, err := r.q.GetUserSession(ctx, postgres.GetUserSessionParams{
		Uuid:     *sessionUUID,
		UserUuid: *userUUID,
	})
	if err != nil {
		if noRowsErr := isNoRowsError(err, "sessions.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("sessions.internalServerError", err)
	}

	domainSession := toDomainUserSession(session)
	return &domainSession, nil
}

func (r *SessionsPostgresRepository) RotateJTI(ctx context.Context, userUUIDStr string, sessionUUIDStr string, currentJTI string, nextJTI string) error {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return err
	}

	rows, err := r.q.RotateUserSessionJTI(ctx, postgres.RotateUserSessionJTIParams{
		Uuid:       *sessionUUID,
		UserUuid:   *userUUID,
		CurrentJti: currentJTI,
		NextJti:    nextJTI,
	})
	if err != nil {
		return domain.NewInternalServerError("sessions.internalServerError", err)
	}
	if rows == 0 {
		return domain.NewNotFoundError("sessions.notFound")
	}
	return nil
}

func (r *SessionsPostgresRepository) Delete(ctx context.Context, userUUIDStr string, sessionUUIDStr string) error {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return err
	}

	if err := r.q.DeleteUserSession(ctx, postgres.DeleteUserSessionParams{
		Uuid:     *sessionUUID,
		UserUuid: *userUUID,
	}); err != nil {
		return domain.NewInternalServerError("sessions.internalServerError", err)
	}
	return nil
}

func (r *SessionsPostgresRepository) DeleteExpiredByUser(ctx context.Context, userUUIDStr string, idleTimeout time.Duration) error {
	userUUID, err := parseUsersUUID(userUUIDStr)
	if err != nil {
		return err
	}

	if err := r.q.DeleteExpiredUserSessionsByUser(ctx, postgres.DeleteExpiredUserSessionsByUserParams{
		UserUuid:    *userUUID,
		IdleTimeout: pgtype.Interval{Microseconds: idleTimeout.Microseconds(), Valid: true},
	}); err != nil {
		return domain.NewInternalServerError("sessions.internalServerError", err)
	}
	return nil
}

func (r *SessionsPostgresRepository) DeleteOldestBeyond(ctx context.Context, userUUIDStr string, keep int) error {
	userUUID, err := parseUsersUUID(userUUIDStr)
	if err != nil {
		return err
	}

	if err := r.q.DeleteOldestUserSessionsBeyond(ctx, postgres.DeleteOldestUserSessionsBeyondParams{
		UserUuid: *userUUID,
		Keep:     int32(keep),
	}); err != nil {
		return domain.NewInternalServerError("sessions.internalServerError", err)
	}
	return nil
}

func toDomainUserSession(session postgres.UserSession) domain.UserSession {
	return domain.UserSession{
		UUID:       uuid.UUID(session.Uuid.Bytes).String(),
		UserUUID:   uuid.UUID(session.UserUuid.Bytes).String(),
		CurrentJTI: session.CurrentJti,
		CreatedAt:  session.CreatedAt.Time.Unix(),
		LastUsedAt: session.LastUsedAt.Time.Unix(),
		ExpiresAt:  session.ExpiresAt.Time.Unix(),
	}
}

func parseSessionUUIDs(userUUIDStr string, sessionUUIDStr string) (*pgtype.UUID, *pgtype.UUID, error) {
	userUUID, err := parseUsersUUID(userUUIDStr)
	if err != nil {
		return nil, nil, err
	}

	sessionUUID, err := parseUUID(sessionUUIDStr, "sessions.invalidUUID")
	if err != nil {
		return nil, nil, err
	}

	return userUUID, sessionUUID, nil
}
