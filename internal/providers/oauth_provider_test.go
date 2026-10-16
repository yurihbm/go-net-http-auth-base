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
)

func TestOAuthProviders_GetUserInfo(t *testing.T) {
	cases := []struct {
		name        string
		newProvider func(t *testing.T, infoURL string) domain.OAuthProvider
	}{
		{
			name: "google",
			newProvider: func(t *testing.T, infoURL string) domain.OAuthProvider {
				cfg, _ := newVerifierCapturingTokenConfig(t)
				return providers.NewGoogleOAuthProvider(cfg, infoURL)
			},
		},
		{
			name: "microsoft",
			newProvider: func(t *testing.T, infoURL string) domain.OAuthProvider {
				cfg, _ := newVerifierCapturingTokenConfig(t)
				return providers.NewMicrosoftOAuthProvider(cfg, infoURL)
			},
		},
		{
			name: "github",
			newProvider: func(t *testing.T, infoURL string) domain.OAuthProvider {
				cfg, _ := newVerifierCapturingTokenConfig(t)
				return providers.NewGitHubOAuthProvider(cfg, infoURL)
			},
		},
	}

	for _, tc := range cases {
		t.Run("error - context cancellation is propagated - "+tc.name, func(t *testing.T) {
			release := make(chan struct{})
			infoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(infoServer.Close)
			t.Cleanup(func() { close(release) })

			provider := tc.newProvider(t, infoServer.URL)
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
