package providers

import (
	"context"
	"errors"
	"go-net-http-auth-base/internal/domain"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

var githubAPIHeaders = http.Header{
	"Accept":               {"application/vnd.github+json"},
	"X-Github-Api-Version": {"2022-11-28"},
}

type githubOAuthProvider struct {
	baseOAuthProvider
}

func NewGitHubOAuthProvider(config oauth2.Config, infoURL ...string) domain.OAuthProvider {
	return &githubOAuthProvider{
		newBaseOAuthProvider("GitHub", config, "https://api.github.com/user", infoURL),
	}
}

func (p *githubOAuthProvider) GetUserInfo(ctx context.Context, code string, codeVerifier string) (*domain.OAuthProviderUserInfo, error) {
	tokens, err := p.exchange(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	var githubUser githubUserInfo
	if err := p.fetch(ctx, p.infoURL, tokens.AccessToken, &githubUser, githubAPIHeaders); err != nil {
		return nil, err
	}

	var emails []githubEmail
	if err := p.fetch(ctx, p.infoURL+"/emails", tokens.AccessToken, &emails, githubAPIHeaders); err != nil {
		return nil, err
	}

	name := githubUser.Name
	if name == "" {
		name = githubUser.Login
	}

	for _, email := range emails {
		if email.Primary {
			return &domain.OAuthProviderUserInfo{
				ID:            strconv.FormatInt(githubUser.ID, 10),
				Name:          name,
				Email:         email.Email,
				EmailVerified: email.Verified,
			}, nil
		}
	}

	return nil, errors.New("failed to find primary email from GitHub")
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type githubUserInfo struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Login string `json:"login"`
}
