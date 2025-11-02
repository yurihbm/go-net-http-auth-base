package domain

import "time"

type TokenAudience string

const (
	TokenAudienceAccess     TokenAudience = "access_token"
	TokenAudienceRefresh    TokenAudience = "refresh_token"
	TokenAudienceExchange   TokenAudience = "exchange_token"
	TokenAudienceOAuthState TokenAudience = "oauth_state_token"
)

const (
	TokenExpirationAccess     = time.Minute * 15   // 15 minutes
	TokenExpirationRefresh    = time.Hour * 24 * 7 // 7 days
	TokenExpirationExchange   = time.Minute        // 1 minute
	TokenExpirationOAuthState = time.Minute * 5    // 5 minutes
)

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type CredentialsLoginDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password"`
}

type RefreshTokenDTO struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type VerifyTokenDTO struct {
	Token    string        `json:"token" validate:"required"`
	Audience TokenAudience `json:"audience" validate:"required,oneof=access_token refresh_token exchange_token oauth_state_token"`
}

type GenerateTokenDTO struct {
	Subject  string        `json:"subject" validate:"required"`
	Audience TokenAudience `json:"token_audience" validate:"required,oneof=access_token refresh_token exchange_token oauth_state_token"`
}

type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
)

type UserOAuthProvider struct {
	UUID           string        `json:"uuid"`
	UserUUID       string        `json:"user_uuid"`
	Provider       OAuthProvider `json:"provider"`
	ProviderUserID string        `json:"provider_user_id"`
	ProviderEmail  string        `json:"provider_email"`
	CreatedAt      int64         `json:"created_at"`
}

type AddUserOAuthProviderDTO struct {
	UserUUID       string        `json:"user_uuid" validate:"required"`
	Provider       OAuthProvider `json:"provider" validate:"required,oneof=google"`
	ProviderUserID string        `json:"provider_user_id" validate:"required"`
	ProviderEmail  string        `json:"provider_email" validate:"required,email"`
}

type GetUserOAuthProviderDTO struct {
	Provider       OAuthProvider `json:"provider" validate:"required,oneof=google"`
	ProviderUserID string        `json:"provider_user_id" validate:"required"`
}

type RemoveUserOAuthProviderDTO struct {
	UserUUID     string `json:"user_uuid" validate:"required"`
	ProviderUUID string `json:"provider_uuid" validate:"required"`
}

type AuthService interface {
	CredentialsLogin(CredentialsLoginDTO) (AuthTokens, error)
	RefreshToken(RefreshTokenDTO) (AuthTokens, error)
	VerifyToken(VerifyTokenDTO) (string, error)
	GenerateToken(GenerateTokenDTO) (string, error)
	AddUserOAuthProvider(AddUserOAuthProviderDTO) (*UserOAuthProvider, error)
	GetUserOAuthProvider(GetUserOAuthProviderDTO) (*UserOAuthProvider, error)
	RemoveUserOAuthProvider(RemoveUserOAuthProviderDTO) error
	GetUserOAuthProvidersByUserUUID(userUUID string) ([]UserOAuthProvider, error)
}

type AuthRepository interface {
	CreateUserOAuthProvider(UserOAuthProvider) (*UserOAuthProvider, error)
	GetUserOAuthProviderByProviderAndProviderUserID(OAuthProvider, string) (*UserOAuthProvider, error)
	DeleteUserOAuthProvider(string) error
	ListUserOAuthProvidersByUserUUID(string) ([]UserOAuthProvider, error)
}
