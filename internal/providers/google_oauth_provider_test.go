package providers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/providers"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func encodeJSON(t *testing.T, w http.ResponseWriter, v any) {
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		t.Fatalf("failed to encode JSON: %v", err)
	}
}

var config = oauth2.Config{
	ClientID:     "test-client-id",
	ClientSecret: "test-client-secret",
	RedirectURL:  "http://localhost:8080/callback",
	Scopes:       []string{"email", "profile"},
}

func TestNewGoogleOAuthProvider(t *testing.T) {
	provider := providers.NewGoogleOAuthProvider(config)

	assert.NotNil(t, provider)
}

func TestGoogleOAuthProvider_GetAuthURL(t *testing.T) {
	provider := providers.NewGoogleOAuthProvider(config)
	state := "test-state"

	authURL := provider.GetAuthURL(state)

	assert.Contains(t, authURL, "state="+state)
}

func TestGoogleOAuthProvider_GetUserInfo(t *testing.T) {
	t.Run("success - fetches user info correctly", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "Bearer test-access-token", r.Header.Get("Authorization"))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			encodeJSON(t, w, domain.OAuthProviderUserInfo{
				Id:    "google-user-123",
				Name:  "John Doe",
				Email: "john@example.com",
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

		provider := providers.NewGoogleOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.NoError(t, err)
		assert.NotNil(t, userInfo)
		assert.Equal(t, "google-user-123", userInfo.Id)
		assert.Equal(t, "John Doe", userInfo.Name)
		assert.Equal(t, "john@example.com", userInfo.Email)
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

		provider := providers.NewGoogleOAuthProvider(testConfig, "http://example.com/userinfo")
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

		provider := providers.NewGoogleOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.Equal(t, "failed to fetch user info from Google", err.Error())
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

		provider := providers.NewGoogleOAuthProvider(testConfig, userInfoServer.URL)
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

		provider := providers.NewGoogleOAuthProvider(testConfig, "http://invalid-unreachable-host:9999/userinfo")
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.Error(t, err)
		assert.Nil(t, userInfo)
	})

	t.Run("success - custom info URL is used", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			encodeJSON(t, w, domain.OAuthProviderUserInfo{
				Id:    "user-456",
				Name:  "Jane Doe",
				Email: "jane@example.com",
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

		provider := providers.NewGoogleOAuthProvider(testConfig, userInfoServer.URL)
		ctx := context.Background()

		userInfo, err := provider.GetUserInfo(ctx, "test-auth-code")

		assert.NoError(t, err)
		assert.NotNil(t, userInfo)
		assert.Equal(t, "user-456", userInfo.Id)
		assert.Equal(t, "Jane Doe", userInfo.Name)
		assert.Equal(t, "jane@example.com", userInfo.Email)
	})
}
