package providers

import (
	"context"
	"go-net-http-auth-base/internal/domain"

	"golang.org/x/oauth2"
)

type googleOAuthProvider struct {
	baseOAuthProvider
}

func NewGoogleOAuthProvider(config oauth2.Config, infoURL ...string) domain.OAuthProvider {
	return &googleOAuthProvider{
		newBaseOAuthProvider("Google", config, "https://www.googleapis.com/oauth2/v2/userinfo", infoURL),
	}
}

func (p *googleOAuthProvider) GetUserInfo(ctx context.Context, code string, codeVerifier string) (*domain.OAuthProviderUserInfo, error) {
	tokens, err := p.exchange(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	var googleUser googleUserInfo
	if err := p.fetch(ctx, p.infoURL, tokens.AccessToken, &googleUser); err != nil {
		return nil, err
	}

	return &domain.OAuthProviderUserInfo{
		ID:            googleUser.ID,
		Name:          googleUser.Name,
		Email:         googleUser.Email,
		EmailVerified: googleUser.VerifiedEmail,
	}, nil
}

type googleUserInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}
