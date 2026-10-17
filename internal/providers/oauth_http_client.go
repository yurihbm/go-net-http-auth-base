package providers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var oauthHTTPTimeout = 10 * time.Second

func withOAuthHTTPClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: oauthHTTPTimeout})
}

var errUnexpectedStatus = errors.New("unexpected status")

type baseOAuthProvider struct {
	name    string
	config  oauth2.Config
	infoURL string
}

func newBaseOAuthProvider(name string, config oauth2.Config, defaultInfoURL string, infoURL []string) baseOAuthProvider {
	urlToUse := defaultInfoURL
	if len(infoURL) > 0 && infoURL[0] != "" {
		urlToUse = infoURL[0]
	}
	return baseOAuthProvider{name: name, config: config, infoURL: urlToUse}
}

func (p *baseOAuthProvider) GetAuthURL(_ context.Context, state string, codeVerifier string) string {
	return p.config.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))
}

func (p *baseOAuthProvider) exchange(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error) {
	return p.config.Exchange(withOAuthHTTPClient(ctx), code, oauth2.VerifierOption(codeVerifier))
}

func (p *baseOAuthProvider) fetch(ctx context.Context, url, accessToken string, target any, headers ...http.Header) error {
	err := fetchJSON(ctx, url, accessToken, target, headers...)
	if errors.Is(err, errUnexpectedStatus) {
		return errors.New("failed to fetch user info from " + p.name)
	}
	return err
}

func fetchJSON(ctx context.Context, url, accessToken string, target any, headers ...http.Header) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	for _, h := range headers {
		for key, values := range h {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: oauthHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return errUnexpectedStatus
	}

	return json.NewDecoder(resp.Body).Decode(target)
}
