package domain

import (
	"context"
	"time"
)

type TokenAudience string

const (
	TokenAudienceAccess            TokenAudience = "access_token"
	TokenAudienceRefresh           TokenAudience = "refresh_token"
	TokenAudienceExchange          TokenAudience = "exchange_token"
	TokenAudienceOAuthState        TokenAudience = "oauth_state_token"
	TokenAudienceEmailVerification TokenAudience = "email_verification_token"
)

const (
	TokenExpirationAccess            = time.Minute * 15   // 15 minutes
	TokenExpirationRefresh           = time.Hour * 24 * 7 // 7 days
	TokenExpirationExchange          = time.Minute        // 1 minute
	TokenExpirationOAuthState        = time.Minute * 5    // 5 minutes
	TokenExpirationEmailVerification = time.Hour * 24     // 24 hours
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
	ID         string        `json:"id,omitempty"`
	AuthTime   int64         `json:"auth_time,omitempty"`
	Role       UserRole      `json:"role,omitempty"`
	Payload    any           `json:"payload,omitempty"`
}

type GenerateTokenDTO struct {
	Subject  string        `json:"subject"`
	Audience TokenAudience `json:"token_audience"`
	ID       string        `json:"id,omitempty"`
	AuthTime int64         `json:"auth_time,omitempty"`
	Role     UserRole      `json:"role,omitempty"`
	Payload  any           `json:"payload,omitempty"`
}

type LogoutDTO struct {
	AccessToken string
}

type VerifyEmailDTO struct {
	Token string `json:"token" validate:"required"`
}

type ResendVerificationDTO struct {
	Email string `json:"email" validate:"required,email"`
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

type StartOAuthLoginDTO struct {
	Provider    OAuthProviderName
	RedirectURI string
}

type StartOAuthLoginResult struct {
	AuthURL      string
	Nonce        string
	CodeVerifier string
}

type OAuthLoginDTO struct {
	Provider     OAuthProviderName
	State        string
	Code         string
	Nonce        string
	CodeVerifier string
}

type VerifyOAuthStateDTO struct {
	Provider OAuthProviderName
	State    string
	Nonce    string
}

type OAuthLoginResult struct {
	User        *User
	Tokens      AuthTokens
	RedirectURI string
}

type OAuthProvider interface {
	GetAuthURL(ctx context.Context, state string, codeVerifier string) string
	GetUserInfo(ctx context.Context, code string, codeVerifier string) (*OAuthProviderUserInfo, error)
}

type OAuthProviderRegistry interface {
	Get(name OAuthProviderName) (OAuthProvider, error)
	GetAll() map[OAuthProviderName]OAuthProvider
	IsConfigured(name OAuthProviderName) bool
}

type TokenGenerator interface {
	GenerateToken(context.Context, GenerateTokenDTO) (string, error)
}

type TokenService interface {
	TokenGenerator
	VerifyToken(context.Context, VerifyTokenDTO) (*VerifiedTokenData, error)
}

type AuthService interface {
	CredentialsLogin(context.Context, CredentialsLoginDTO) (AuthTokens, error)
	RefreshToken(context.Context, RefreshTokenDTO) (AuthTokens, error)
	Logout(context.Context, LogoutDTO) error
	VerifyToken(context.Context, VerifyTokenDTO) (*VerifiedTokenData, error)
	GenerateToken(context.Context, GenerateTokenDTO) (string, error)
	AddUserOAuthProvider(context.Context, AddUserOAuthProviderDTO) (*UserOAuthProvider, error)
	GetUserOAuthProvider(context.Context, GetUserOAuthProviderDTO) (*UserOAuthProvider, error)
	RemoveUserOAuthProvider(context.Context, RemoveUserOAuthProviderDTO) error
	GetUserOAuthProvidersByUserUUID(context.Context, string) ([]UserOAuthProvider, error)
	StartOAuthLogin(context.Context, StartOAuthLoginDTO) (*StartOAuthLoginResult, error)
	GetOAuthProviderUserInfo(ctx context.Context, provider OAuthProviderName, code string, codeVerifier string) (*OAuthProviderUserInfo, error)
	VerifyOAuthState(context.Context, VerifyOAuthStateDTO) (string, error)
	OAuthLogin(context.Context, OAuthLoginDTO) (*OAuthLoginResult, error)
}

type AuthRepository interface {
	CreateUserOAuthProvider(context.Context, UserOAuthProvider) (*UserOAuthProvider, error)
	GetUserOAuthProviderByProviderAndProviderUserID(context.Context, OAuthProviderName, string) (*UserOAuthProvider, error)
	DeleteUserOAuthProvider(context.Context, string) error
	ListUserOAuthProvidersByUserUUID(context.Context, string) ([]UserOAuthProvider, error)
}
