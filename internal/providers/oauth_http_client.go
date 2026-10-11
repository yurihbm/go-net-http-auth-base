package providers

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var oauthHTTPTimeout = 10 * time.Second

func withOAuthHTTPClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: oauthHTTPTimeout})
}
