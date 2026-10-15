package providers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestNewGitHubOAuthProvider(t *testing.T) {
	provider := providers.NewGitHubOAuthProvider(config)

	assert.NotNil(t, provider)
}

func TestGitHubOAuthProvider_GetAuthURL(t *testing.T) {
	provider := providers.NewGitHubOAuthProvider(config)
	state := "test-state"

	authURL := provider.GetAuthURL(context.Background(), state, testCodeVerifier)

	assert.Contains(t, authURL, "state="+state)
	assertPKCEChallenge(t, authURL)
}

func TestGitHubOAuthProvider_GetUserInfo_SendsCodeVerifier(t *testing.T) {
	cfg, receivedVerifier := newVerifierCapturingTokenConfig(t)
	provider := providers.NewGitHubOAuthProvider(cfg)

	_, _ = provider.GetUserInfo(context.Background(), "test-auth-code", testCodeVerifier)

	assert.Equal(t, testCodeVerifier, *receivedVerifier)
}

func TestGitHubOAuthProvider_GetUserInfo(t *testing.T) {
	t.Run("success - fetches user info correctly", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "Bearer test-access-token", r.Header.Get("Authorization"))
			assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
			assert.Equal(t, "2022-11-28", r.Header.Get("X-GitHub-Api-Version"))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if r.URL.Path == "/user/emails" {
				encodeJSON(t, w, []map[string]any{
					{"email": "other@example.com", "primary": false, "verified": true},
					{"email": "john@example.com", "primary": true, "verified": true},
				})
				return
			}
			encodeJSON(t, w, map[string]any{
				"id":    12345,
				"name":  "John Doe",
				"email": "public@example.com",
			})
		}))
		defer userInfoServer.Close()

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				encodeJSON(t, w, map[string]any{
					"access_token": "test-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			}
		}))
		defer tokenServer.Close()

		testConfig := oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"read:user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewGitHubOAuthProvider(testConfig, userInfoServer.URL+"/user")
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code", testCodeVerifier)

		assert.NoError(t, err)
		assert.NotNil(t, userInfo)
		assert.Equal(t, "12345", userInfo.ID)
		assert.Equal(t, "John Doe", userInfo.Name)
		assert.Equal(t, "john@example.com", userInfo.Email)
		assert.True(t, userInfo.EmailVerified)
	})

	t.Run("error - code exchange fails", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("invalid code"))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer tokenServer.Close()

		testConfig := oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"read:user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewGitHubOAuthProvider(testConfig, "http://example.com/user")
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "invalid-code", testCodeVerifier)

		assert.Error(t, err)
		assert.Nil(t, userInfo)
	})

	t.Run("error - user info endpoint returns non-200 status", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer userInfoServer.Close()

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				encodeJSON(t, w, map[string]any{
					"access_token": "test-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			}
		}))
		defer tokenServer.Close()

		testConfig := oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"read:user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewGitHubOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code", testCodeVerifier)

		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.Equal(t, "failed to fetch user info from GitHub", err.Error())
	})

	t.Run("error - invalid JSON response from user info endpoint", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("invalid json"))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer userInfoServer.Close()

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				encodeJSON(t, w, map[string]any{
					"access_token": "test-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			}
		}))
		defer tokenServer.Close()

		testConfig := oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"read:user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewGitHubOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code", testCodeVerifier)

		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.True(t, strings.Contains(err.Error(), "invalid character"))
	})

	t.Run("error - user info endpoint is unreachable", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				encodeJSON(t, w, map[string]any{
					"access_token": "test-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
			}
		}))
		defer tokenServer.Close()

		testConfig := oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"read:user"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewGitHubOAuthProvider(testConfig, "http://invalid-unreachable-host:9999/user")
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code", testCodeVerifier)

		assert.Error(t, err)
		assert.Nil(t, userInfo)
	})

	emailsCases := []struct {
		name         string
		emailsStatus int
		emails       any
		wantErr      bool
		wantEmail    string
		wantVerified bool
	}{
		{
			name:         "primary but unverified email is not verified",
			emailsStatus: http.StatusOK,
			emails: []map[string]any{
				{"email": "john@example.com", "primary": true, "verified": false},
			},
			wantEmail: "john@example.com",
		},
		{
			name:         "error - no primary email",
			emailsStatus: http.StatusOK,
			emails: []map[string]any{
				{"email": "john@example.com", "primary": false, "verified": true},
			},
			wantErr: true,
		},
		{
			name:         "error - emails endpoint fails",
			emailsStatus: http.StatusForbidden,
			emails:       map[string]any{"message": "forbidden"},
			wantErr:      true,
		},
	}

	for _, tc := range emailsCases {
		t.Run(tc.name, func(t *testing.T) {
			userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/user/emails" {
					w.WriteHeader(tc.emailsStatus)
					encodeJSON(t, w, tc.emails)
					return
				}
				w.WriteHeader(http.StatusOK)
				encodeJSON(t, w, map[string]any{"id": 12345, "name": "John Doe", "email": "public@example.com"})
			}))
			defer userInfoServer.Close()

			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				encodeJSON(t, w, map[string]any{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600})
			}))
			defer tokenServer.Close()

			testConfig := oauth2.Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Endpoint:     oauth2.Endpoint{TokenURL: tokenServer.URL + "/token"},
			}

			provider := providers.NewGitHubOAuthProvider(testConfig, userInfoServer.URL+"/user")

			userInfo, err := provider.GetUserInfo(context.Background(), "test-auth-code", testCodeVerifier)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, userInfo)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantEmail, userInfo.Email)
			assert.Equal(t, tc.wantVerified, userInfo.EmailVerified)
		})
	}

	t.Run("exchange times out", func(t *testing.T) {
		provider := providers.NewGitHubOAuthProvider(newHangingTokenConfig(t), "http://example.com/user")

		start := time.Now()
		userInfo, err := provider.GetUserInfo(context.Background(), "test-auth-code", testCodeVerifier)

		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.Less(t, time.Since(start), 2*time.Second)
	})
}
