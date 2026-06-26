package domain

import (
	"context"
	"time"
)

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

type OAuthProviderName string

const (
	OAuthProviderGoogle    OAuthProviderName = "google"
	OAuthProviderMicrosoft OAuthProviderName = "microsoft"
	OAuthProviderGitHub    OAuthProviderName = "github"
)

func (e OAuthProviderName) IsValid() bool {
	switch e {
	case OAuthProviderGoogle:
		return true
	case OAuthProviderMicrosoft:
		return true
	case OAuthProviderGitHub:
		return true
	default:
		return false
	}
}

type OAuthProviderUserInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type UserOAuthProvider struct {
	UUID           string            `json:"uuid"`
	UserUUID       string            `json:"user_uuid"`
	Provider       OAuthProviderName `json:"provider"`
	ProviderUserID string            `json:"provider_user_id"`
	ProviderEmail  string            `json:"provider_email"`
	CreatedAt      int64             `json:"created_at"`
}

type CredentialsLoginDTO struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenDTO struct {
	RefreshToken string `json:"refresh_token"`
}

type VerifyTokenDTO struct {
	Token    string        `json:"token"`
	Audience TokenAudience `json:"audience"`
}

type VerifiedTokenData struct {
	Subject    string        `json:"subject"`
	Audience   TokenAudience `json:"audience"`
	Expiration int64         `json:"expiration"`
	Payload    any           `json:"payload,omitempty"`
}

type GenerateTokenDTO struct {
	Subject  string        `json:"subject"`
	Audience TokenAudience `json:"token_audience"`
	Payload  any           `json:"payload,omitempty"`
}

type AddUserOAuthProviderDTO struct {
	UserUUID       string            `json:"user_uuid"`
	Provider       OAuthProviderName `json:"provider"`
	ProviderUserID string            `json:"provider_user_id"`
	ProviderEmail  string            `json:"provider_email"`
}

type GetUserOAuthProviderDTO struct {
	Provider       OAuthProviderName `json:"provider"`
	ProviderUserID string            `json:"provider_user_id"`
}

type RemoveUserOAuthProviderDTO struct {
	UserUUID     string `json:"user_uuid"`
	ProviderUUID string `json:"provider_uuid"`
}

type OAuthProvider interface {
	GetAuthURL(context.Context, string) string
	GetUserInfo(context.Context, string) (*OAuthProviderUserInfo, error)
}

type OAuthProviderRegistry interface {
	Get(name OAuthProviderName) (OAuthProvider, error)
	GetAll() map[OAuthProviderName]OAuthProvider
	IsConfigured(name OAuthProviderName) bool
}

type AuthService interface {
	CredentialsLogin(context.Context, CredentialsLoginDTO) (AuthTokens, error)
	RefreshToken(context.Context, RefreshTokenDTO) (AuthTokens, error)
	VerifyToken(context.Context, VerifyTokenDTO) (*VerifiedTokenData, error)
	GenerateToken(context.Context, GenerateTokenDTO) (string, error)
	AddUserOAuthProvider(context.Context, AddUserOAuthProviderDTO) (*UserOAuthProvider, error)
	GetUserOAuthProvider(context.Context, GetUserOAuthProviderDTO) (*UserOAuthProvider, error)
	RemoveUserOAuthProvider(context.Context, RemoveUserOAuthProviderDTO) error
	GetUserOAuthProvidersByUserUUID(context.Context, string) ([]UserOAuthProvider, error)
	GetOAuthProviderAuthURL(context.Context, OAuthProviderName, string) (string, error)
	GetOAuthProviderUserInfo(context.Context, OAuthProviderName, string) (*OAuthProviderUserInfo, error)
}

type AuthRepository interface {
	CreateUserOAuthProvider(context.Context, UserOAuthProvider) (*UserOAuthProvider, error)
	GetUserOAuthProviderByProviderAndProviderUserID(context.Context, OAuthProviderName, string) (*UserOAuthProvider, error)
	DeleteUserOAuthProvider(context.Context, string) error
	ListUserOAuthProvidersByUserUUID(context.Context, string) ([]UserOAuthProvider, error)
}
