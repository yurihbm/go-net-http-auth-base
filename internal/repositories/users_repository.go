package repositories

import (
	"context"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type UsersPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.UsersRepository = (*UsersPostgresRepository)(nil)

func NewUsersPostgresRepository(db postgres.DBTX) domain.UsersRepository {
	return &UsersPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *UsersPostgresRepository) FindByUUID(ctx context.Context, uuidStr string) (*domain.User, error) {
	uuid, err := parseUsersUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	user, err := r.q.GetUserByUUID(ctx, *uuid)
	if err != nil {
		if noRowsErr := isNoRowsError(err, "users.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("users.internalServerError", err)
	}

	domainUser := toDomainUser(user)
	return &domainUser, nil
}

func (r *UsersPostgresRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if noRowsErr := isNoRowsError(err, "users.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("users.internalServerError", err)
	}

	domainUser := toDomainUser(user)
	return &domainUser, nil
}

func (r *UsersPostgresRepository) Create(ctx context.Context, user domain.User) (*domain.User, error) {
	params := postgres.CreateUserParams{
		Name:         user.Name,
		Email:        user.Email,
		PasswordHash: pgtype.Text{String: user.PasswordHash, Valid: true},
	}

	createdUser, err := r.q.CreateUser(ctx, params)
	if err != nil {
		if conflictErr := isConflictError(err, "users.email.conflict"); conflictErr != nil {
			return nil, conflictErr
		}
		return nil, domain.NewInternalServerError("users.internalServerError", err)
	}

	// Update the user object with the data from the database
	user = toDomainUser(createdUser)
	return &user, nil
}

func (r *UsersPostgresRepository) Update(ctx context.Context, user domain.User) error {
	uuid, err := parseUsersUUID(user.UUID)
	if err != nil {
		return err
	}

	params := postgres.UpdateUserParams{
		Uuid:  *uuid,
		Name:  user.Name,
		Email: user.Email,
	}

	if user.PasswordHash != "" {
		params.PasswordHash = pgtype.Text{String: user.PasswordHash, Valid: true}
	}

	if err = r.q.UpdateUser(ctx, params); err != nil {
		if conflictErr := isConflictError(err, "users.email.conflict"); conflictErr != nil {
			return conflictErr
		}
		return domain.NewInternalServerError("users.internalServerError", err)
	}

	return nil
}

func (r *UsersPostgresRepository) Delete(ctx context.Context, uuidStr string) error {
	uuid, err := parseUsersUUID(uuidStr)
	if err != nil {
		return err
	}

	err = r.q.DeleteUser(ctx, *uuid)
	if err != nil {
		return domain.NewInternalServerError("user.internalServerError", err)
	}
	return nil
}

func toDomainUser(user postgres.User) domain.User {
	var uuidBytes = user.Uuid.Bytes
	return domain.User{
		UUID:         uuid.UUID(uuidBytes).String(),
		Name:         user.Name,
		Email:        user.Email,
		Role:         domain.UserRole(user.Role),
		PasswordHash: user.PasswordHash.String,
		CreatedAt:    user.CreatedAt.Time.Unix(),
		UpdatedAt:    user.UpdatedAt.Time.Unix(),
	}
}

func parseUsersUUID(uuidStr string) (*pgtype.UUID, error) {
	return parseUUID(uuidStr, "users.invalidUserUUID")
}
