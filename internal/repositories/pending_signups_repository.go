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

type PendingSignupsPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.PendingSignupRepository = (*PendingSignupsPostgresRepository)(nil)

func NewPendingSignupsPostgresRepository(db postgres.DBTX) domain.PendingSignupRepository {
	return &PendingSignupsPostgresRepository{q: postgres.New(db)}
}

func (r *PendingSignupsPostgresRepository) Create(ctx context.Context, pending domain.PendingSignup) (*domain.PendingSignup, error) {
	pendingUUID, err := parseUUID(pending.UUID, "auth.signup.invalidUUID")
	if err != nil {
		return nil, err
	}

	codeExpiresAt := time.Unix(pending.CodeExpiresAt, 0)
	expiresAt := time.Unix(pending.ExpiresAt, 0)
	created, err := r.q.CreatePendingSignup(ctx, postgres.CreatePendingSignupParams{
		Uuid:           *pendingUUID,
		Kind:           postgres.PendingSignupKind(pending.Kind),
		Name:           pending.Name,
		Email:          pending.Email,
		PasswordHash:   pgtype.Text{String: pending.PasswordHash, Valid: pending.PasswordHash != ""},
		Provider:       postgres.NullOauthProvider{OauthProvider: postgres.OauthProvider(pending.Provider), Valid: pending.Provider != ""},
		ProviderUserID: pgtype.Text{String: pending.ProviderUserID, Valid: pending.ProviderUserID != ""},
		CodeHash:       pending.CodeHash,
		CodeExpiresAt:  toTimestamptz(&codeExpiresAt),
		ExpiresAt:      toTimestamptz(&expiresAt),
	})
	if err != nil {
		return nil, domain.NewInternalServerError("auth.signup.internalServerError", err)
	}

	return toDomainPendingSignup(created), nil
}

func (r *PendingSignupsPostgresRepository) FindByUUID(ctx context.Context, uuidStr string) (*domain.PendingSignup, error) {
	pendingUUID, err := parsePendingSignupUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	pending, err := r.q.GetPendingSignup(ctx, *pendingUUID)
	return pendingSignupResult(pending, err, domain.ErrSignupNoPending)
}

func (r *PendingSignupsPostgresRepository) Attempt(ctx context.Context, uuidStr string, maxAttempts int) (*domain.PendingSignup, error) {
	pendingUUID, err := parsePendingSignupUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	pending, err := r.q.AttemptPendingSignup(ctx, postgres.AttemptPendingSignupParams{
		Uuid:        *pendingUUID,
		MaxAttempts: int32(maxAttempts),
	})
	return pendingSignupResult(pending, err, domain.ErrSignupNoPending)
}

func (r *PendingSignupsPostgresRepository) Consume(ctx context.Context, uuidStr string, codeHash string) (*domain.PendingSignup, error) {
	pendingUUID, err := parsePendingSignupUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	pending, err := r.q.ConsumePendingSignup(ctx, postgres.ConsumePendingSignupParams{
		Uuid:     *pendingUUID,
		CodeHash: codeHash,
	})
	return pendingSignupResult(pending, err, domain.ErrSignupNoPending)
}

func (r *PendingSignupsPostgresRepository) Resend(ctx context.Context, uuidStr string, codeHash string, codeTTL time.Duration) (*domain.PendingSignup, error) {
	pendingUUID, err := parsePendingSignupUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	pending, err := r.q.ResendPendingSignup(ctx, postgres.ResendPendingSignupParams{
		Uuid:     *pendingUUID,
		CodeHash: codeHash,
		CodeTtl:  toInterval(codeTTL),
	})
	return pendingSignupResult(pending, err, domain.ErrSignupNoPending)
}

func (r *PendingSignupsPostgresRepository) Delete(ctx context.Context, uuidStr string) error {
	pendingUUID, err := parsePendingSignupUUID(uuidStr)
	if err != nil {
		return err
	}

	if err := r.q.DeletePendingSignup(ctx, *pendingUUID); err != nil {
		return domain.NewInternalServerError("auth.signup.internalServerError", err)
	}
	return nil
}

// The pending signup UUID comes from a cookie, so a malformed one is treated
// like a missing signup.
func parsePendingSignupUUID(uuidStr string) (*pgtype.UUID, error) {
	parsed, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, domain.ErrSignupNoPending
	}
	return &pgtype.UUID{Bytes: [16]byte(parsed), Valid: true}, nil
}

func pendingSignupResult(pending postgres.PendingSignup, err error, noRowsErr error) (*domain.PendingSignup, error) {
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("auth.signup.internalServerError", err)
	}
	return toDomainPendingSignup(pending), nil
}

func toDomainPendingSignup(pending postgres.PendingSignup) *domain.PendingSignup {
	return &domain.PendingSignup{
		UUID:           uuid.UUID(pending.Uuid.Bytes).String(),
		Kind:           domain.PendingSignupKind(pending.Kind),
		Name:           pending.Name,
		Email:          pending.Email,
		PasswordHash:   pending.PasswordHash.String,
		Provider:       domain.OAuthProviderName(pending.Provider.OauthProvider),
		ProviderUserID: pending.ProviderUserID.String,
		CodeHash:       pending.CodeHash,
		CodeExpiresAt:  pending.CodeExpiresAt.Time.Unix(),
		ExpiresAt:      pending.ExpiresAt.Time.Unix(),
	}
}
