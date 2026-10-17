package providers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthProviders_GetUserInfo_PropagatesContextCancellation(t *testing.T) {
	cases := map[string]func(t *testing.T, infoURL string) domain.OAuthProvider{
		"google": func(t *testing.T, infoURL string) domain.OAuthProvider {
			cfg, _ := newVerifierCapturingTokenConfig(t)
			return providers.NewGoogleOAuthProvider(cfg, infoURL)
		},
		"microsoft": func(t *testing.T, infoURL string) domain.OAuthProvider {
			cfg, _ := newVerifierCapturingTokenConfig(t)
			return providers.NewMicrosoftOAuthProvider(cfg, infoURL)
		},
	}

	for name, newProvider := range cases {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			infoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(infoServer.Close)
			t.Cleanup(func() { close(release) })

			provider := newProvider(t, infoServer.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			start := time.Now()
			userInfo, err := provider.GetUserInfo(ctx, "code", testCodeVerifier)

			assert.Error(t, err)
			assert.Nil(t, userInfo)
			assert.Less(t, time.Since(start), 2*time.Second)
		})
	}
}

func TestGitHubOAuthProvider_GetUserInfo_NameAndID(t *testing.T) {
	newServer := func(t *testing.T, user map[string]any) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/user/emails" {
				encodeJSON(t, w, []map[string]any{{"email": "john@example.com", "primary": true, "verified": true}})
				return
			}
			encodeJSON(t, w, user)
		}))
		t.Cleanup(server.Close)
		return server.URL + "/user"
	}

	t.Run("falls back to login when name is null", func(t *testing.T) {
		cfg, _ := newVerifierCapturingTokenConfig(t)
		provider := providers.NewGitHubOAuthProvider(cfg, newServer(t, map[string]any{"id": 1, "name": nil, "login": "johnd"}))

		userInfo, err := provider.GetUserInfo(context.Background(), "code", testCodeVerifier)

		require.NoError(t, err)
		assert.Equal(t, "johnd", userInfo.Name)
	})

	t.Run("falls back to login when name is empty", func(t *testing.T) {
		cfg, _ := newVerifierCapturingTokenConfig(t)
		provider := providers.NewGitHubOAuthProvider(cfg, newServer(t, map[string]any{"id": 1, "name": "", "login": "johnd"}))

		userInfo, err := provider.GetUserInfo(context.Background(), "code", testCodeVerifier)

		require.NoError(t, err)
		assert.Equal(t, "johnd", userInfo.Name)
	})

	t.Run("supports ids larger than 32 bits", func(t *testing.T) {
		cfg, _ := newVerifierCapturingTokenConfig(t)
		provider := providers.NewGitHubOAuthProvider(cfg, newServer(t, map[string]any{"id": int64(9007199254740991), "name": "John", "login": "johnd"}))

		userInfo, err := provider.GetUserInfo(context.Background(), "code", testCodeVerifier)

		require.NoError(t, err)
		assert.Equal(t, "9007199254740991", userInfo.ID)
	})
}
