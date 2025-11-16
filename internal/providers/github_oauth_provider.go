package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go-net-http-auth-base/internal/domain"
	"net/http"
	"time"

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

func (p *githubOAuthProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *githubOAuthProvider) GetUserInfo(ctx context.Context, code string) (*domain.OAuthProviderUserInfo, error) {
	tokens, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", p.infoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Println("Failed to close response body:", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch user info from GitHub")
	}

	var githubUser GitHubUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		return nil, err
	}

	userInfo := &domain.OAuthProviderUserInfo{
		ID:    fmt.Sprintf("%d", githubUser.ID),
		Name:  githubUser.Name,
		Email: githubUser.Email,
	}

	return userInfo, nil
}

type GitHubUserInfo struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
