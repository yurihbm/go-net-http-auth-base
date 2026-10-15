package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go-net-http-auth-base/internal/domain"
	"net/http"

	"golang.org/x/oauth2"
)

type githubOAuthProvider struct {
	config  oauth2.Config
	infoURL string
}

func NewGitHubOAuthProvider(config oauth2.Config, infoURL ...string) domain.OAuthProvider {
	urlToUse := "https://api.github.com/user"
	if len(infoURL) > 0 && infoURL[0] != "" {
		urlToUse = infoURL[0]
	}
	return &githubOAuthProvider{
		config,
		urlToUse,
	}
}

func (p *githubOAuthProvider) GetAuthURL(_ context.Context, state string, codeVerifier string) string {
	return p.config.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))
}

func (p *githubOAuthProvider) GetUserInfo(ctx context.Context, code string, codeVerifier string) (*domain.OAuthProviderUserInfo, error) {
	tokens, err := p.config.Exchange(withOAuthHTTPClient(ctx), code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, err
	}

	var githubUser githubUserInfo
	if err := p.fetchJSON(ctx, p.infoURL, tokens.AccessToken, &githubUser); err != nil {
		return nil, err
	}

	var emails []githubEmail
	if err := p.fetchJSON(ctx, p.infoURL+"/emails", tokens.AccessToken, &emails); err != nil {
		return nil, err
	}

	for _, email := range emails {
		if email.Primary {
			return &domain.OAuthProviderUserInfo{
				ID:            fmt.Sprintf("%d", githubUser.ID),
				Name:          githubUser.Name,
				Email:         email.Email,
				EmailVerified: email.Verified,
			}, nil
		}
	}

	return nil, errors.New("failed to find primary email from GitHub")
}

func (p *githubOAuthProvider) fetchJSON(ctx context.Context, url, accessToken string, target any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: oauthHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Println("Failed to close response body:", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to fetch user info from GitHub")
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type githubUserInfo struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}
