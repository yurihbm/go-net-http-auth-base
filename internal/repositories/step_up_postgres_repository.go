package repositories

import (
	"context"
	"errors"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type StepUpPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.StepUpRepository = (*StepUpPostgresRepository)(nil)

func NewStepUpPostgresRepository(db postgres.DBTX) domain.StepUpRepository {
	return &StepUpPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *StepUpPostgresRepository) Upsert(ctx context.Context, challenge domain.StepUpChallenge, cooldown time.Duration) (*domain.StepUpChallenge, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(challenge.UserUUID, challenge.SessionUUID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Unix(challenge.ExpiresAt, 0)
	upserted, err := r.q.UpsertStepUpChallenge(ctx, postgres.UpsertStepUpChallengeParams{
		UserUuid:    *userUUID,
		SessionUuid: *sessionUUID,
		CodeHash:    challenge.CodeHash,
		ExpiresAt:   toTimestamptz(&expiresAt),
		Cooldown:    toInterval(cooldown),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.NewTooManyRequestsError("auth.stepUp.cooldown")
		}
		if fkErr := isForeignKeyViolationError(err, "sessions.notFound"); fkErr != nil {
			return nil, fkErr
		}
		return nil, domain.NewInternalServerError("auth.stepUp.internalServerError", err)
	}

	domainChallenge := toDomainStepUpChallenge(upserted)
	return &domainChallenge, nil
}

func (r *StepUpPostgresRepository) Attempt(ctx context.Context, userUUIDStr string, sessionUUIDStr string, maxAttempts int) (*domain.StepUpChallenge, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return nil, err
	}

	row, err := r.q.AttemptStepUpChallenge(ctx, postgres.AttemptStepUpChallengeParams{
		SessionUuid: *sessionUUID,
		UserUuid:    *userUUID,
		MaxAttempts: int32(maxAttempts),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.NewUnauthorizedError("auth.stepUp.noChallenge")
		}
		return nil, domain.NewInternalServerError("auth.stepUp.internalServerError", err)
	}

	return &domain.StepUpChallenge{
		UserUUID:    userUUIDStr,
		SessionUUID: sessionUUIDStr,
		CodeHash:    row.CodeHash,
		Attempts:    int(row.Attempts),
	}, nil
}

func (r *StepUpPostgresRepository) Delete(ctx context.Context, sessionUUIDStr string) error {
	sessionUUID, err := parseUUID(sessionUUIDStr, "sessions.invalidUUID")
	if err != nil {
		return err
	}

	if err := r.q.DeleteStepUpChallenge(ctx, *sessionUUID); err != nil {
		return domain.NewInternalServerError("auth.stepUp.internalServerError", err)
	}
	return nil
}

func toDomainStepUpChallenge(challenge postgres.StepUpChallenge) domain.StepUpChallenge {
	return domain.StepUpChallenge{
		UserUUID:    uuid.UUID(challenge.UserUuid.Bytes).String(),
		SessionUUID: uuid.UUID(challenge.SessionUuid.Bytes).String(),
		CodeHash:    challenge.CodeHash,
		Attempts:    int(challenge.Attempts),
		ExpiresAt:   challenge.ExpiresAt.Time.Unix(),
		CreatedAt:   challenge.CreatedAt.Time.Unix(),
	}
}
