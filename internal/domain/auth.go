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

type AuthService interface {
	CredentialsLogin(CredentialsLoginDTO) (AuthTokens, error)
	RefreshToken(RefreshTokenDTO) (AuthTokens, error)
	VerifyToken(VerifyTokenDTO) (string, error)
	GenerateToken(GenerateTokenDTO) (string, error)
}
