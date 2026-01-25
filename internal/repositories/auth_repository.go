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
	userUUID, err := parseUsersUUID(provider.UserUUID)
	if err != nil {
		return nil, err
	}

	params := postgres.CreateUserOAuthProviderParams{
		UserUuid:       *userUUID,
		Provider:       postgres.OauthProvider(provider.Provider),
		ProviderUserID: provider.ProviderUserID,
		ProviderEmail:  provider.ProviderEmail,
	}

	createdProvider, err := r.q.CreateUserOAuthProvider(context.Background(), params)
	if err != nil {
		if conflictErr := isConflictError(err, "auth.oauthProvider.conflict"); conflictErr != nil {
			return nil, conflictErr
		}
		if fkErr := isForeignKeyViolationError(err, "auth.user.notFound"); fkErr != nil {
			return nil, fkErr
		}
		if noRowsErr := isNoRowsError(err, "auth.oauthProvider.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("auth.oauthProvider.intervalServerError")
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
		if noRowsErr := isNoRowsError(err, "auth.oauthProvider.notFound"); noRowsErr != nil {
			return nil, noRowsErr
		}
		return nil, domain.NewInternalServerError("auth.oauthProvider.intervalServerError")
	}

	domainProvider := toDomainUserOAuthProvider(foundProvider)
	return &domainProvider, nil
}

func (r *AuthPostgresRepository) DeleteUserOAuthProvider(uuidStr string) error {
	oauthProviderUUID, err := parseUserOAuthProviderUUID(uuidStr)
	if err != nil {
		return err
	}

	err = r.q.DeleteUserOAuthProvider(context.Background(), *oauthProviderUUID)

	if err != nil {
		return domain.NewInternalServerError("auth.oauthProvider.intervalServerError")
	}
	return nil
}

func (r *AuthPostgresRepository) ListUserOAuthProvidersByUserUUID(userUUIDStr string) ([]domain.UserOAuthProvider, error) {
	userUUID, err := parseUsersUUID(userUUIDStr)
	if err != nil {
		return nil, err
	}

	providers, err := r.q.ListUserOAuthProvidersByUserUUID(context.Background(), *userUUID)
	if err != nil {
		return nil, domain.NewInternalServerError("auth.oauthProvider.intervalServerError")
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

func parseUsersUUID(uuidStr string) (*pgtype.UUID, error) {
	return parseUUID(uuidStr, "users.invalidUserUUID")
}

func parseUserOAuthProviderUUID(uuidStr string) (*pgtype.UUID, error) {
	return parseUUID(uuidStr, "users.oauthProvider.invalidUUID")
}
