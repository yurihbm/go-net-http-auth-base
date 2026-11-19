package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	require.Failf(t, "cookie not set", "cookie %q", name)
	return nil
}

func TestSetPendingSignupCookie(t *testing.T) {
	for secure, name := range map[bool]string{true: "__Host-pending_signup", false: "pending_signup"} {
		w := httptest.NewRecorder()

		api.SetPendingSignupCookie(w, "pending-uuid", secure)

		cookie := responseCookie(t, w, name)
		assert.Equal(t, "pending-uuid", cookie.Value)
		assert.Equal(t, "/", cookie.Path)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
		assert.Equal(t, int(domain.PendingSignupTTL.Seconds()), cookie.MaxAge)
		assert.Equal(t, secure, cookie.Secure)
	}
}

func TestDeletePendingSignupCookie(t *testing.T) {
	w := httptest.NewRecorder()

	api.DeletePendingSignupCookie(w, true)

	cookie := responseCookie(t, w, "__Host-pending_signup")
	assert.Empty(t, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.True(t, cookie.Secure)
	assert.Less(t, cookie.MaxAge, 0)
}

func TestSetAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()

	api.SetAuthCookies(w, domain.AuthTokens{AccessToken: "access", RefreshToken: "refresh"}, true)

	access := responseCookie(t, w, api.AccessTokenCookieName)
	assert.Equal(t, "access", access.Value)
	assert.Equal(t, api.AccessTokenCookiePath, access.Path)
	assert.Equal(t, int(domain.TokenExpirationAccess.Seconds()), access.MaxAge)
	assert.True(t, access.HttpOnly)
	assert.True(t, access.Secure)
	assert.Equal(t, http.SameSiteStrictMode, access.SameSite)
	refresh := responseCookie(t, w, api.RefreshTokenCookieName)
	assert.Equal(t, "refresh", refresh.Value)
	assert.Equal(t, api.RefreshTokenCookiePath, refresh.Path)
	assert.Equal(t, int(domain.TokenExpirationRefresh.Seconds()), refresh.MaxAge)
	assert.True(t, refresh.Secure)
}
