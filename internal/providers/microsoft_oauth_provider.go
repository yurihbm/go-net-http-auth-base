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

type microsoftOAuthProvider struct {
	config  oauth2.Config
	infoURL string
}

func NewMicrosoftOAuthProvider(config oauth2.Config, infoURL ...string) domain.OAuthProvider {
	urlToUse := "https://graph.microsoft.com/oidc/userinfo"
	if len(infoURL) > 0 && infoURL[0] != "" {
		urlToUse = infoURL[0]
	}
	return &microsoftOAuthProvider{
		config,
		urlToUse,
	}
}

func (p *microsoftOAuthProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *microsoftOAuthProvider) GetUserInfo(ctx context.Context, code string) (*domain.OAuthProviderUserInfo, error) {
	tokens, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", p.infoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

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
		return nil, errors.New("failed to fetch user info from Microsoft")
	}

	var microsoftUser microsoftUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&microsoftUser); err != nil {
		return nil, err
	}

	userInfo := &domain.OAuthProviderUserInfo{
		ID:    microsoftUser.ID,
		Name:  microsoftUser.Name,
		Email: microsoftUser.Email,
	}

	return userInfo, nil

}

type microsoftUserInfo struct {
	ID    string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
