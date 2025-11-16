package config

import (
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

func NewGoogleOAuthConfig() oauth2.Config {
	return oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("API_URL") + "/auth/google/callback",
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}
}

func NewGitHubOAuthConfig() oauth2.Config {
	return oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("API_URL") + "/auth/github/callback",
		Endpoint:     github.Endpoint,
		Scopes: []string{
			"read:user",
		},
	}
}

func NewMicrosoftOAuthConfig() oauth2.Config {
	return oauth2.Config{
		ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
		ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("API_URL") + "/auth/microsoft/callback",
		Endpoint:     microsoft.AzureADEndpoint(""),
		Scopes: []string{
			"User.Read",
		},
	}
}
