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

func (r *UsersPostgresRepository) FindByUUID(uuidStr string) (*domain.User, error) {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, err
	}

	user, err := r.q.GetUserByUUID(context.Background(), pgtype.UUID{Bytes: [16]byte(uuid), Valid: true})
	if err != nil {
		return nil, err
	}

	domainUser := toDomainUser(user)
	return &domainUser, nil
}

func (r *UsersPostgresRepository) FindByEmail(email string) (*domain.User, error) {
	user, err := r.q.GetUserByEmail(context.Background(), email)
	if err != nil {
		return nil, err
	}

	domainUser := toDomainUser(user)
	return &domainUser, nil
}

func (r *UsersPostgresRepository) Create(user domain.User) (*domain.User, error) {
	params := postgres.CreateUserParams{
		Name:         user.Name,
		Email:        user.Email,
		PasswordHash: pgtype.Text{String: user.PasswordHash, Valid: true},
	}

	createdUser, err := r.q.CreateUser(context.Background(), params)
	if err != nil {
		return nil, err
	}

	// Update the user object with the data from the database
	user = toDomainUser(createdUser)
	return &user, nil
}

func (r *UsersPostgresRepository) Update(user domain.User) error {
	uuid, err := uuid.Parse(user.UUID)
	if err != nil {
		return err
	}

	params := postgres.UpdateUserParams{
		Uuid:  pgtype.UUID{Bytes: [16]byte(uuid), Valid: true},
		Name:  user.Name,
		Email: user.Email,
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

func toDomainUser(user postgres.User) domain.User {
	var uuidBytes = user.Uuid.Bytes
	return domain.User{
		UUID:         uuid.UUID(uuidBytes).String(),
		Name:         user.Name,
		Email:        user.Email,
		PasswordHash: user.PasswordHash.String,
		CreatedAt:    user.CreatedAt.Time.Unix(),
		UpdatedAt:    user.UpdatedAt.Time.Unix(),
	}
}
