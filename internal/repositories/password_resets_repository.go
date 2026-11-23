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

type PasswordResetsPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.PasswordResetRepository = (*PasswordResetsPostgresRepository)(nil)

func NewPasswordResetsPostgresRepository(db postgres.DBTX) domain.PasswordResetRepository {
	return &PasswordResetsPostgresRepository{q: postgres.New(db)}
}

func (r *PasswordResetsPostgresRepository) Create(ctx context.Context, reset domain.PasswordReset) (*domain.PasswordReset, error) {
	resetUUID, err := parseUUID(reset.UUID, "auth.passwordReset.invalidUUID")
	if err != nil {
		return nil, err
	}
	userUUID, err := parseUUID(reset.UserUUID, "users.invalidUserUUID")
	if err != nil {
		return nil, err
	}

	expiresAt := time.Unix(reset.ExpiresAt, 0)
	created, err := r.q.CreatePasswordReset(ctx, postgres.CreatePasswordResetParams{
		Uuid:         *resetUUID,
		UserUuid:     *userUUID,
		Email:        reset.Email,
		EmailVersion: int32(reset.EmailVersion),
		CodeHash:     reset.CodeHash,
		ExpiresAt:    toTimestamptz(&expiresAt),
	})
	if err != nil {
		return nil, domain.NewInternalServerError("auth.passwordReset.internalServerError", err)
	}

	return toDomainPasswordReset(created), nil
}

func (r *PasswordResetsPostgresRepository) FindByUUID(ctx context.Context, uuidStr string) (*domain.PasswordReset, error) {
	resetUUID, err := parsePasswordResetUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	reset, err := r.q.GetPasswordReset(ctx, *resetUUID)
	return passwordResetResult(reset, err)
}

func (r *PasswordResetsPostgresRepository) Attempt(ctx context.Context, uuidStr string, maxAttempts int) (*domain.PasswordReset, error) {
	resetUUID, err := parsePasswordResetUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	reset, err := r.q.AttemptPasswordReset(ctx, postgres.AttemptPasswordResetParams{
		Uuid:        *resetUUID,
		MaxAttempts: int32(maxAttempts),
	})
	return passwordResetResult(reset, err)
}

func (r *PasswordResetsPostgresRepository) Consume(ctx context.Context, uuidStr string, codeHash string) (*domain.PasswordReset, error) {
	resetUUID, err := parsePasswordResetUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	reset, err := r.q.ConsumePasswordReset(ctx, postgres.ConsumePasswordResetParams{
		Uuid:     *resetUUID,
		CodeHash: codeHash,
	})
	return passwordResetResult(reset, err)
}

func (r *PasswordResetsPostgresRepository) Delete(ctx context.Context, uuidStr string) error {
	resetUUID, err := parsePasswordResetUUID(uuidStr)
	if err != nil {
		return err
	}

	if err := r.q.DeletePasswordReset(ctx, *resetUUID); err != nil {
		return domain.NewInternalServerError("auth.passwordReset.internalServerError", err)
	}
	return nil
}

func (r *PasswordResetsPostgresRepository) DeleteByUser(ctx context.Context, userUUID string) error {
	parsed, err := parseUsersUUID(userUUID)
	if err != nil {
		return err
	}

	if err := r.q.DeletePasswordResetsByUser(ctx, *parsed); err != nil {
		return domain.NewInternalServerError("auth.passwordReset.internalServerError", err)
	}
	return nil
}

// The reset UUID comes from a cookie, so a malformed one is treated like a
// missing reset.
func parsePasswordResetUUID(uuidStr string) (*pgtype.UUID, error) {
	parsed, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, domain.ErrPasswordResetInvalidCode
	}
	return &pgtype.UUID{Bytes: [16]byte(parsed), Valid: true}, nil
}

func passwordResetResult(reset postgres.PasswordReset, err error) (*domain.PasswordReset, error) {
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrPasswordResetInvalidCode
		}
		return nil, domain.NewInternalServerError("auth.passwordReset.internalServerError", err)
	}
	return toDomainPasswordReset(reset), nil
}

func toDomainPasswordReset(reset postgres.PasswordReset) *domain.PasswordReset {
	return &domain.PasswordReset{
		UUID:         uuid.UUID(reset.Uuid.Bytes).String(),
		UserUUID:     uuid.UUID(reset.UserUuid.Bytes).String(),
		Email:        reset.Email,
		EmailVersion: int(reset.EmailVersion),
		CodeHash:     reset.CodeHash,
		Attempts:     int(reset.Attempts),
		ExpiresAt:    reset.ExpiresAt.Time.Unix(),
	}
}
