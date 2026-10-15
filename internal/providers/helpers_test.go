package providers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

const testCodeVerifier = "test-code-verifier-0123456789-0123456789-abcdef"

func assertPKCEChallenge(t *testing.T, authURL string) {
	t.Helper()

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, oauth2.S256ChallengeFromVerifier(testCodeVerifier), parsed.Query().Get("code_challenge"))
	assert.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
}

func newVerifierCapturingTokenConfig(t *testing.T) (oauth2.Config, *string) {
	t.Helper()

	var receivedVerifier string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		receivedVerifier = r.PostForm.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(t, w, map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(tokenServer.Close)

	return oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint:     oauth2.Endpoint{TokenURL: tokenServer.URL + "/token"},
	}, &receivedVerifier
}
