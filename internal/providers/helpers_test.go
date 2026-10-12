package providers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-net-http-auth-base/internal/providers"

	"golang.org/x/oauth2"
)

func encodeJSON(t *testing.T, w http.ResponseWriter, v any) {
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		t.Fatalf("failed to encode JSON: %v", err)
	}
}

func newHangingTokenConfig(t *testing.T) oauth2.Config {
	t.Helper()

	t.Cleanup(providers.SetOAuthHTTPTimeout(50 * time.Millisecond))

	release := make(chan struct{})
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(tokenServer.Close)
	t.Cleanup(func() { close(release) })

	return oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint:     oauth2.Endpoint{TokenURL: tokenServer.URL + "/token"},
	}
}
