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

type googleOAuthProvider struct {
	config  oauth2.Config
	infoURL string
}

func NewGoogleOAuthProvider(config oauth2.Config, infoURL ...string) domain.OAuthProvider {
	urlToUse := "https://www.googleapis.com/oauth2/v2/userinfo"
	if len(infoURL) > 0 && infoURL[0] != "" {
		urlToUse = infoURL[0]
	}
	return &googleOAuthProvider{
		config,
		urlToUse,
	}
}

func (p *googleOAuthProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *googleOAuthProvider) GetUserInfo(ctx context.Context, code string) (*domain.OAuthProviderUserInfo, error) {
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
		return nil, errors.New("failed to fetch user info from Google")
	}

	var userInfo domain.OAuthProviderUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil

}
