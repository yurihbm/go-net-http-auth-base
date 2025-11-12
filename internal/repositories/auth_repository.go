package repositories

import (
	"context"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type AuthPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.AuthRepository = (*AuthPostgresRepository)(nil)

func NewAuthPostgresRepository(db postgres.DBTX) domain.AuthRepository {
	return &AuthPostgresRepository{
		q: postgres.New(db),
	}
}

func (r *AuthPostgresRepository) CreateUserOAuthProvider(provider domain.UserOAuthProvider) (*domain.UserOAuthProvider, error) {
	userUUID, err := uuid.Parse(provider.UserUUID)
	if err != nil {
		return nil, err
	}

	params := postgres.CreateUserOAuthProviderParams{
		UserUuid:       pgtype.UUID{Bytes: [16]byte(userUUID), Valid: true},
		Provider:       postgres.OauthProvider(provider.Provider),
		ProviderUserID: provider.ProviderUserID,
		ProviderEmail:  provider.ProviderEmail,
	}

	createdProvider, err := r.q.CreateUserOAuthProvider(context.Background(), params)
	if err != nil {
		return nil, err
	}

	domainProvider := toDomainUserOAuthProvider(createdProvider)
	return &domainProvider, nil
}

func (r *AuthPostgresRepository) GetUserOAuthProviderByProviderAndProviderUserID(provider domain.OAuthProviderName, providerUserID string) (*domain.UserOAuthProvider, error) {
	params := postgres.GetUserOAuthProviderByProviderAndProviderUserIDParams{
		Provider:       postgres.OauthProvider(provider),
		ProviderUserID: providerUserID,
	}

	foundProvider, err := r.q.GetUserOAuthProviderByProviderAndProviderUserID(context.Background(), params)
	if err != nil {
		return nil, err
	}

	domainProvider := toDomainUserOAuthProvider(foundProvider)
	return &domainProvider, nil
}

func (r *AuthPostgresRepository) DeleteUserOAuthProvider(uuidStr string) error {
	parsedUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return err
	}

	return r.q.DeleteUserOAuthProvider(context.Background(), pgtype.UUID{Bytes: [16]byte(parsedUUID), Valid: true})
}

func (r *AuthPostgresRepository) ListUserOAuthProvidersByUserUUID(userUUID string) ([]domain.UserOAuthProvider, error) {
	parsedUUID, err := uuid.Parse(userUUID)
	if err != nil {
		return nil, err
	}

	providers, err := r.q.ListUserOAuthProvidersByUserUUID(context.Background(), pgtype.UUID{Bytes: [16]byte(parsedUUID), Valid: true})
	if err != nil {
		return nil, err
	}

	domainProviders := make([]domain.UserOAuthProvider, len(providers))
	for i, provider := range providers {
		domainProviders[i] = toDomainUserOAuthProvider(provider)
	}

	return domainProviders, nil
}

func toDomainUserOAuthProvider(provider postgres.UserOauthProvider) domain.UserOAuthProvider {
	var uuidBytes = provider.Uuid.Bytes
	var userUuidBytes = provider.UserUuid.Bytes
	return domain.UserOAuthProvider{
		UUID:           uuid.UUID(uuidBytes).String(),
		UserUUID:       uuid.UUID(userUuidBytes).String(),
		Provider:       domain.OAuthProviderName(provider.Provider),
		ProviderUserID: provider.ProviderUserID,
		ProviderEmail:  provider.ProviderEmail,
		CreatedAt:      provider.CreatedAt.Time.Unix(),
	}
}
