package config

import (
	"go-net-http-auth-base/internal/domain"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var OAuthConfig = map[domain.OAuthProvider]oauth2.Config{
	domain.OAuthProviderGoogle: {
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("API_URL") + "/auth/google/callback",
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	},
}
