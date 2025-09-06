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

func NewUsersPostgresRepository(db postgres.DBTX) domain.UsersRepository {
	return &UsersPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *UsersPostgresRepository) FindByUUID(uuidStr string) (*domain.User, error) {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, err
	}

	user, err := r.q.GetUserByUUID(context.Background(), pgtype.UUID{Bytes: [16]byte(uuid), Valid: true})
	if err != nil {
		return nil, err
	}

	return toDomainUser(user), nil
}

func (r *UsersPostgresRepository) Create(user *domain.User) error {
	params := postgres.CreateUserParams{
		Name:       user.Name,
		Email:      user.Email,
		AuthMethod: postgres.AuthMethodEnum(user.AuthMethod),
	}

	if user.PasswordHash != "" {
		params.PasswordHash = pgtype.Text{String: user.PasswordHash, Valid: true}
	}

	createdUser, err := r.q.CreateUser(context.Background(), params)
	if err != nil {
		return err
	}

	// Update the user object with the data from the database
	*user = *toDomainUser(createdUser)
	return nil
}

func (r *UsersPostgresRepository) Update(user *domain.User) error {
	uuid, err := uuid.Parse(user.UUID)
	if err != nil {
		return err
	}

	params := postgres.UpdateUserParams{
		Uuid:       pgtype.UUID{Bytes: [16]byte(uuid), Valid: true},
		Name:       user.Name,
		Email:      user.Email,
		AuthMethod: postgres.AuthMethodEnum(user.AuthMethod),
	}

	if user.PasswordHash != "" {
		params.PasswordHash = pgtype.Text{String: user.PasswordHash, Valid: true}
	}

	if err = r.q.UpdateUser(context.Background(), params); err != nil {
		return err
	}

	return nil
}

func (r *UsersPostgresRepository) Delete(uuidStr string) error {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return err
	}

	return r.q.DeleteUser(context.Background(), pgtype.UUID{Bytes: [16]byte(uuid), Valid: true})
}

func toDomainUser(user postgres.User) *domain.User {
	var uuidBytes = user.Uuid.Bytes
	return &domain.User{
		UUID:         uuid.UUID(uuidBytes).String(),
		Name:         user.Name,
		Email:        user.Email,
		PasswordHash: user.PasswordHash.String,
		CreatedAt:    user.CreatedAt.Time.Unix(),
		UpdatedAt:    user.UpdatedAt.Time.Unix(),
		AuthMethod:   domain.AuthMethod(user.AuthMethod),
	}
}
