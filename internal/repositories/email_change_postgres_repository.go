package repositories

import (
	"context"
	"errors"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type EmailChangePostgresRepository struct {
	q *postgres.Queries
}

var _ domain.EmailChangeRepository = (*EmailChangePostgresRepository)(nil)

func NewEmailChangePostgresRepository(db postgres.DBTX) domain.EmailChangeRepository {
	return &EmailChangePostgresRepository{
		q: postgres.New(db),
	}
}

func (r *EmailChangePostgresRepository) Upsert(ctx context.Context, challenge domain.EmailChangeChallenge, cooldown time.Duration) (*domain.EmailChangeChallenge, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(challenge.UserUUID, challenge.SessionUUID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Unix(challenge.ExpiresAt, 0)
	upserted, err := r.q.UpsertEmailChangeChallenge(ctx, postgres.UpsertEmailChangeChallengeParams{
		UserUuid:     *userUUID,
		SessionUuid:  *sessionUUID,
		NewEmail:     challenge.NewEmail,
		EmailVersion: int32(challenge.EmailVersion),
		CodeHash:     challenge.CodeHash,
		ExpiresAt:    toTimestamptz(&expiresAt),
		Cooldown:     pgtype.Interval{Microseconds: cooldown.Microseconds(), Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.NewTooManyRequestsError("users.emailChange.cooldown")
		}
		if fkErr := isForeignKeyViolationError(err, "sessions.notFound"); fkErr != nil {
			return nil, fkErr
		}
		return nil, domain.NewInternalServerError("users.emailChange.internalServerError", err)
	}

	domainChallenge := toDomainEmailChangeChallenge(upserted)
	return &domainChallenge, nil
}

func (r *EmailChangePostgresRepository) Attempt(ctx context.Context, userUUIDStr string, sessionUUIDStr string, maxAttempts int) (*domain.EmailChangeChallenge, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return nil, err
	}

	row, err := r.q.AttemptEmailChangeChallenge(ctx, postgres.AttemptEmailChangeChallengeParams{
		SessionUuid: *sessionUUID,
		UserUuid:    *userUUID,
		MaxAttempts: int32(maxAttempts),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrEmailChangeNoChallenge
		}
		return nil, domain.NewInternalServerError("users.emailChange.internalServerError", err)
	}

	challenge := toDomainEmailChangeChallenge(row)
	return &challenge, nil
}

func (r *EmailChangePostgresRepository) Delete(ctx context.Context, sessionUUIDStr string) error {
	sessionUUID, err := parseUUID(sessionUUIDStr, "sessions.invalidUUID")
	if err != nil {
		return err
	}

	if err := r.q.DeleteEmailChangeChallenge(ctx, *sessionUUID); err != nil {
		return domain.NewInternalServerError("users.emailChange.internalServerError", err)
	}
	return nil
}

func toDomainEmailChangeChallenge(challenge postgres.EmailChangeChallenge) domain.EmailChangeChallenge {
	return domain.EmailChangeChallenge{
		UserUUID:     uuid.UUID(challenge.UserUuid.Bytes).String(),
		SessionUUID:  uuid.UUID(challenge.SessionUuid.Bytes).String(),
		NewEmail:     challenge.NewEmail,
		EmailVersion: int(challenge.EmailVersion),
		CodeHash:     challenge.CodeHash,
		Attempts:     int(challenge.Attempts),
		ExpiresAt:    challenge.ExpiresAt.Time.Unix(),
		CreatedAt:    challenge.CreatedAt.Time.Unix(),
	}
}
