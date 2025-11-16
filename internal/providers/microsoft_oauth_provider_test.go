package providers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestNewMicrosoftOAuthProvider(t *testing.T) {
	provider := providers.NewMicrosoftOAuthProvider(config)

	assert.NotNil(t, provider)
}

func TestMicrosoftOAuthProvider_GetAuthURL(t *testing.T) {
	provider := providers.NewMicrosoftOAuthProvider(config)
	state := "test-state"

	authURL := provider.GetAuthURL(state)

	assert.Contains(t, authURL, "state="+state)
}

func TestMicrosoftOAuthProvider_GetUserInfo(t *testing.T) {
	t.Run("success - fetches user info correctly", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "Bearer test-access-token", r.Header.Get("Authorization"))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			encodeJSON(t, w, map[string]any{
				"sub":   "microsoft-user-123",
				"name":  "Jane Doe",
				"email": "jane@example.com",
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
			Scopes:       []string{"email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewMicrosoftOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.NoError(t, err)
		assert.NotNil(t, userInfo)
		assert.Equal(t, "microsoft-user-123", userInfo.ID)
		assert.Equal(t, "Jane Doe", userInfo.Name)
		assert.Equal(t, "jane@example.com", userInfo.Email)
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
			Scopes:       []string{"email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewMicrosoftOAuthProvider(testConfig, "http://example.com/userinfo")
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "invalid-code")

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
			Scopes:       []string{"email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewMicrosoftOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.Equal(t, "failed to fetch user info from Microsoft", err.Error())
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
			Scopes:       []string{"email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewMicrosoftOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

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
			Scopes:       []string{"email", "profile"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenServer.URL + "/auth",
				TokenURL: tokenServer.URL + "/token",
			},
		}

		provider := providers.NewMicrosoftOAuthProvider(testConfig, "http://invalid-unreachable-host:9999/userinfo")
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.Error(t, err)
		assert.Nil(t, userInfo)
	})
}
