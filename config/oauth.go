package config

import (
	"go-net-http-auth-base/internal/domain"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

func GetOAuthConfig(provider domain.OAuthProviderName) *oauth2.Config {
	switch provider {
	case domain.OAuthProviderGoogle:
		return &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("API_URL") + "/auth/google/callback",
			Endpoint:     google.Endpoint,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
		}
	default:
		return nil
	}
}

var GoogleOAuthConfig = oauth2.Config{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("API_URL") + "/auth/google/callback",
	Endpoint:     google.Endpoint,
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
}

var GitHubOAuthConfig = oauth2.Config{
	ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
	ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("API_URL") + "/auth/github/callback",
	Endpoint:     github.Endpoint,
	Scopes: []string{
		"read:user",
	},
}
