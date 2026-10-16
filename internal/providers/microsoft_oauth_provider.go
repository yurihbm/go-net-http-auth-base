package providers

import (
	"context"
	"go-net-http-auth-base/internal/domain"

	"golang.org/x/oauth2"
)

type microsoftOAuthProvider struct {
	baseOAuthProvider
}

func NewMicrosoftOAuthProvider(config oauth2.Config, infoURL ...string) domain.OAuthProvider {
	return &microsoftOAuthProvider{
		newBaseOAuthProvider("Microsoft", config, "https://graph.microsoft.com/oidc/userinfo", infoURL),
	}
}

func (p *microsoftOAuthProvider) GetUserInfo(ctx context.Context, code string, codeVerifier string) (*domain.OAuthProviderUserInfo, error) {
	tokens, err := p.exchange(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	var microsoftUser microsoftUserInfo
	if err := p.fetch(ctx, p.infoURL, tokens.AccessToken, &microsoftUser); err != nil {
		return nil, err
	}

	return &domain.OAuthProviderUserInfo{
		ID:            microsoftUser.ID,
		Name:          microsoftUser.Name,
		Email:         microsoftUser.Email,
		EmailVerified: microsoftUser.EmailVerified,
	}, nil
}

type microsoftUserInfo struct {
	ID            string `json:"sub"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}
