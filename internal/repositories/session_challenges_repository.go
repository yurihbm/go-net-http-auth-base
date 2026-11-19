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

type sessionChallengeErrors struct {
	cooldown    string
	noChallenge error
	internal    string
}

var sessionChallengeErrorsByPurpose = map[domain.SessionChallengePurpose]sessionChallengeErrors{
	domain.SessionChallengeStepUp:      {"auth.stepUp.cooldown", domain.ErrStepUpNoChallenge, "auth.stepUp.internalServerError"},
	domain.SessionChallengeEmailChange: {"users.emailChange.cooldown", domain.ErrEmailChangeNoChallenge, "users.emailChange.internalServerError"},
}

type SessionChallengesPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.SessionChallengeRepository = (*SessionChallengesPostgresRepository)(nil)

func NewSessionChallengesPostgresRepository(db postgres.DBTX) domain.SessionChallengeRepository {
	return &SessionChallengesPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *SessionChallengesPostgresRepository) Upsert(ctx context.Context, challenge domain.SessionChallenge, cooldown time.Duration) error {
	errs := sessionChallengeErrorsByPurpose[challenge.Purpose]
	userUUID, sessionUUID, err := parseSessionUUIDs(challenge.UserUUID, challenge.SessionUUID)
	if err != nil {
		return err
	}

	expiresAt := time.Unix(challenge.ExpiresAt, 0)
	upserted, err := r.q.UpsertSessionChallenge(ctx, postgres.UpsertSessionChallengeParams{
		UserUuid:     *userUUID,
		SessionUuid:  *sessionUUID,
		Purpose:      postgres.SessionChallengePurpose(challenge.Purpose),
		NewEmail:     pgtype.Text{String: challenge.NewEmail, Valid: challenge.Purpose == domain.SessionChallengeEmailChange},
		EmailVersion: pgtype.Int4{Int32: int32(challenge.EmailVersion), Valid: challenge.Purpose == domain.SessionChallengeEmailChange},
		CodeHash:     challenge.CodeHash,
		ExpiresAt:    toTimestamptz(&expiresAt),
		Cooldown:     toInterval(cooldown),
	})
	if err != nil {
		if fkErr := isForeignKeyViolationError(err, "sessions.notFound"); fkErr != nil {
			return fkErr
		}
		return domain.NewInternalServerError(errs.internal, err)
	}
	if upserted == 0 {
		return domain.NewTooManyRequestsError(errs.cooldown)
	}
	return nil
}

func (r *SessionChallengesPostgresRepository) Find(ctx context.Context, userUUIDStr string, sessionUUIDStr string, purpose domain.SessionChallengePurpose) (*domain.SessionChallenge, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return nil, err
	}

	row, err := r.q.GetSessionChallenge(ctx, postgres.GetSessionChallengeParams{
		SessionUuid: *sessionUUID,
		UserUuid:    *userUUID,
		Purpose:     postgres.SessionChallengePurpose(purpose),
	})
	return sessionChallengeResult(row, err, purpose)
}

func (r *SessionChallengesPostgresRepository) Attempt(ctx context.Context, userUUIDStr string, sessionUUIDStr string, purpose domain.SessionChallengePurpose, maxAttempts int) (*domain.SessionChallenge, error) {
	userUUID, sessionUUID, err := parseSessionUUIDs(userUUIDStr, sessionUUIDStr)
	if err != nil {
		return nil, err
	}

	row, err := r.q.AttemptSessionChallenge(ctx, postgres.AttemptSessionChallengeParams{
		SessionUuid: *sessionUUID,
		UserUuid:    *userUUID,
		Purpose:     postgres.SessionChallengePurpose(purpose),
		MaxAttempts: int32(maxAttempts),
	})
	return sessionChallengeResult(row, err, purpose)
}

func (r *SessionChallengesPostgresRepository) Delete(ctx context.Context, sessionUUIDStr string, purpose domain.SessionChallengePurpose) error {
	sessionUUID, err := parseUUID(sessionUUIDStr, "sessions.invalidUUID")
	if err != nil {
		return err
	}

	err = r.q.DeleteSessionChallenge(ctx, postgres.DeleteSessionChallengeParams{
		SessionUuid: *sessionUUID,
		Purpose:     postgres.SessionChallengePurpose(purpose),
	})
	if err != nil {
		return domain.NewInternalServerError(sessionChallengeErrorsByPurpose[purpose].internal, err)
	}
	return nil
}

func sessionChallengeResult(row postgres.SessionChallenge, err error, purpose domain.SessionChallengePurpose) (*domain.SessionChallenge, error) {
	if err != nil {
		errs := sessionChallengeErrorsByPurpose[purpose]
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.noChallenge
		}
		return nil, domain.NewInternalServerError(errs.internal, err)
	}
	challenge := toDomainSessionChallenge(row)
	return &challenge, nil
}

func toDomainSessionChallenge(challenge postgres.SessionChallenge) domain.SessionChallenge {
	return domain.SessionChallenge{
		UserUUID:     uuid.UUID(challenge.UserUuid.Bytes).String(),
		SessionUUID:  uuid.UUID(challenge.SessionUuid.Bytes).String(),
		Purpose:      domain.SessionChallengePurpose(challenge.Purpose),
		NewEmail:     challenge.NewEmail.String,
		EmailVersion: int(challenge.EmailVersion.Int32),
		CodeHash:     challenge.CodeHash,
		ExpiresAt:    challenge.ExpiresAt.Time.Unix(),
	}
}
