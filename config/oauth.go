package config

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

func NewGoogleOAuthConfig(creds OAuthProviderCredentials, apiURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		RedirectURL:  apiURL + "/auth/google/callback",
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}
}

func NewGitHubOAuthConfig(creds OAuthProviderCredentials, apiURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		RedirectURL:  apiURL + "/auth/github/callback",
		Endpoint:     github.Endpoint,
		Scopes: []string{
			"read:user",
			"user:email",
		},
	}
}

func NewMicrosoftOAuthConfig(creds OAuthProviderCredentials, apiURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		RedirectURL:  apiURL + "/auth/microsoft/callback",
		Endpoint:     microsoft.AzureADEndpoint(""),
		Scopes: []string{
			"User.Read",
		},
	}
}
