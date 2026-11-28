package repositories

import (
	"context"
	"errors"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	featureFlagUsersFlagFK = "feature_flag_users_flag_uuid_fkey"
	featureFlagUsersUserFK = "feature_flag_users_user_uuid_fkey"
)

type FeatureFlagsPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.FeatureFlagsRepository = (*FeatureFlagsPostgresRepository)(nil)

func NewFeatureFlagsPostgresRepository(db postgres.DBTX) domain.FeatureFlagsRepository {
	return &FeatureFlagsPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *FeatureFlagsPostgresRepository) Create(ctx context.Context, flag domain.FeatureFlag) (*domain.FeatureFlag, error) {
	created, err := r.q.CreateFeatureFlag(ctx, postgres.CreateFeatureFlagParams{
		Key:             flag.Key,
		Description:     flag.Description,
		EnabledGlobally: flag.EnabledGlobally,
	})
	if err != nil {
		if conflictErr := isConflictError(err, "featureFlags.key.conflict"); conflictErr != nil {
			return nil, conflictErr
		}
		return nil, domain.NewInternalServerError("featureFlags.internalServerError", err)
	}

	domainFlag := toDomainFeatureFlag(created)
	return &domainFlag, nil
}

func (r *FeatureFlagsPostgresRepository) FindDetailsByUUID(ctx context.Context, uuidStr string) (*domain.FeatureFlagDetails, error) {
	flagUUID, err := parseFeatureFlagUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	row, err := r.q.GetFeatureFlagDetailsByUUID(ctx, *flagUUID)
	if err != nil {
		if noRowsErr := isNoRowsError(err, "featureFlags.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("featureFlags.internalServerError", err)
	}

	users := make([]string, 0, len(row.UserUuids))
	for _, userUUID := range row.UserUuids {
		users = append(users, uuid.UUID(userUUID.Bytes).String())
	}

	return &domain.FeatureFlagDetails{
		FeatureFlag: toDomainFeatureFlag(postgres.FeatureFlag{
			Uuid:            row.Uuid,
			Key:             row.Key,
			Description:     row.Description,
			EnabledGlobally: row.EnabledGlobally,
			CreatedAt:       row.CreatedAt,
			UpdatedAt:       row.UpdatedAt,
		}),
		UserUUIDs: users,
	}, nil
}

func (r *FeatureFlagsPostgresRepository) Update(ctx context.Context, uuidStr string, dto domain.UpdateFeatureFlagDTO) (*domain.FeatureFlag, error) {
	flagUUID, err := parseFeatureFlagUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	var description pgtype.Text
	if dto.Description != nil {
		description = pgtype.Text{String: *dto.Description, Valid: true}
	}

	var enabledGlobally pgtype.Bool
	if dto.EnabledGlobally != nil {
		enabledGlobally = pgtype.Bool{Bool: *dto.EnabledGlobally, Valid: true}
	}

	updated, err := r.q.UpdateFeatureFlag(ctx, postgres.UpdateFeatureFlagParams{
		Uuid:            *flagUUID,
		Description:     description,
		EnabledGlobally: enabledGlobally,
	})
	if err != nil {
		if noRowsErr := isNoRowsError(err, "featureFlags.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("featureFlags.internalServerError", err)
	}

	domainFlag := toDomainFeatureFlag(updated)
	return &domainFlag, nil
}

func (r *FeatureFlagsPostgresRepository) Delete(ctx context.Context, uuidStr string) error {
	flagUUID, err := parseFeatureFlagUUID(uuidStr)
	if err != nil {
		return err
	}

	deleted, err := r.q.DeleteFeatureFlag(ctx, *flagUUID)
	if err != nil {
		return domain.NewInternalServerError("featureFlags.internalServerError", err)
	}
	if deleted == 0 {
		return domain.NewNotFoundError("featureFlags.notFound")
	}
	return nil
}

func (r *FeatureFlagsPostgresRepository) List(ctx context.Context, dto domain.ListFeatureFlagsDTO) ([]domain.FeatureFlag, int64, error) {
	var cursor pgtype.UUID
	if dto.Cursor != nil {
		parsed, err := parseUUID(*dto.Cursor, "featureFlags.invalidCursor")
		if err != nil {
			return nil, 0, err
		}
		cursor = *parsed
	}

	total, err := r.q.CountFeatureFlags(ctx)
	if err != nil {
		return nil, 0, domain.NewInternalServerError("featureFlags.internalServerError", err)
	}

	rows, err := r.q.ListFeatureFlags(ctx, postgres.ListFeatureFlagsParams{
		Cursor:   cursor,
		PageSize: int64(dto.Limit),
	})
	if err != nil {
		return nil, 0, domain.NewInternalServerError("featureFlags.internalServerError", err)
	}

	flags := make([]domain.FeatureFlag, 0, len(rows))
	for _, row := range rows {
		flags = append(flags, toDomainFeatureFlag(row))
	}

	return flags, total, nil
}

func (r *FeatureFlagsPostgresRepository) AddUser(ctx context.Context, flagUUIDStr string, userUUIDStr string) error {
	flagUUID, err := parseFeatureFlagUUID(flagUUIDStr)
	if err != nil {
		return err
	}
	userUUID, err := parseUsersUUID(userUUIDStr)
	if err != nil {
		return err
	}

	err = r.q.AddFeatureFlagUser(ctx, postgres.AddFeatureFlagUserParams{
		FlagUuid: *flagUUID,
		UserUuid: *userUUID,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
			switch pgErr.ConstraintName {
			case featureFlagUsersFlagFK:
				return domain.NewNotFoundError("featureFlags.notFound")
			case featureFlagUsersUserFK:
				return domain.NewNotFoundError("users.notFound")
			}
		}
		return domain.NewInternalServerError("featureFlags.internalServerError", err)
	}
	return nil
}

func (r *FeatureFlagsPostgresRepository) RemoveUser(ctx context.Context, flagUUIDStr string, userUUIDStr string) error {
	flagUUID, err := parseFeatureFlagUUID(flagUUIDStr)
	if err != nil {
		return err
	}
	userUUID, err := parseUsersUUID(userUUIDStr)
	if err != nil {
		return err
	}

	removed, err := r.q.RemoveFeatureFlagUser(ctx, postgres.RemoveFeatureFlagUserParams{
		FlagUuid: *flagUUID,
		UserUuid: *userUUID,
	})
	if err != nil {
		return domain.NewInternalServerError("featureFlags.internalServerError", err)
	}
	if removed == 0 {
		return domain.NewNotFoundError("featureFlags.users.notFound")
	}
	return nil
}

func (r *FeatureFlagsPostgresRepository) ListEnabledKeys(ctx context.Context, userUUIDStr *string) ([]string, error) {
	var userUUID pgtype.UUID
	if userUUIDStr != nil {
		parsed, err := parseUsersUUID(*userUUIDStr)
		if err != nil {
			return nil, err
		}
		userUUID = *parsed
	}

	keys, err := r.q.ListEnabledFeatureFlagKeys(ctx, userUUID)
	if err != nil {
		return nil, domain.NewInternalServerError("featureFlags.internalServerError", err)
	}
	return keys, nil
}

func parseFeatureFlagUUID(uuidStr string) (*pgtype.UUID, error) {
	return parseUUID(uuidStr, "featureFlags.invalidFlagUUID")
}

func toDomainFeatureFlag(flag postgres.FeatureFlag) domain.FeatureFlag {
	return domain.FeatureFlag{
		UUID:            uuid.UUID(flag.Uuid.Bytes).String(),
		Key:             flag.Key,
		Description:     flag.Description,
		EnabledGlobally: flag.EnabledGlobally,
		CreatedAt:       flag.CreatedAt.Time.Unix(),
		UpdatedAt:       flag.UpdatedAt.Time.Unix(),
	}
}
