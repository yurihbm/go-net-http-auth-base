package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignupAndLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	c := newClient(t)
	dto := domain.CreateUserDTO{Name: "Jane Doe", Email: "jane.doe@example.com", Password: "password123"}

	pending := c.do(http.MethodPost, "/users", dto)
	require.Equal(t, http.StatusAccepted, pending.Status)
	assert.Equal(t, "users.create.pending", pending.Body.Message)
	pendingCookie := c.cookie(api.OAuthFlowCookieName(api.PendingSignupCookieName, false))
	require.NotNil(t, pendingCookie)
	code := mailbox.otpCode(t, dto.Email)

	t.Run("no account exists before the code is verified", func(t *testing.T) {
		resp := newClient(t).login(dto.Email, dto.Password)

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
	})

	t.Run("another browser without the cookie cannot verify the code", func(t *testing.T) {
		resp := newClient(t).do(http.MethodPost, "/auth/signup/verify", domain.CodeDTO{Code: code})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.signup.noPending", resp.Body.Error)
	})

	var user domain.User
	t.Run("verifying the code creates the account and signs in", func(t *testing.T) {
		resp := c.do(http.MethodPost, "/auth/signup/verify", domain.CodeDTO{Code: code})

		require.Equal(t, http.StatusCreated, resp.Status)
		assert.Equal(t, "auth.signup.success", resp.Body.Message)
		require.NoError(t, json.Unmarshal(resp.Body.Data, &user))
		assert.Equal(t, dto.Email, user.Email)
		assert.NotNil(t, c.cookie(api.AccessTokenCookieName))
		assert.NotNil(t, c.cookie(api.RefreshTokenCookieName))
		assert.Nil(t, c.cookie(api.OAuthFlowCookieName(api.PendingSignupCookieName, false)))
	})

	t.Run("me returns the signed up user", func(t *testing.T) {
		resp := c.do(http.MethodGet, "/users/me", nil)

		require.Equal(t, http.StatusOK, resp.Status)
		var me domain.User
		require.NoError(t, json.Unmarshal(resp.Body.Data, &me))
		assert.Equal(t, user, me)
	})

	t.Run("replaying the code is rejected", func(t *testing.T) {
		replay := newClient(t)
		base, err := url.Parse(serverURL)
		require.NoError(t, err)
		replay.jar.SetCookies(base, []*http.Cookie{{Name: pendingCookie.Name, Value: pendingCookie.Value, Path: "/"}})

		resp := replay.do(http.MethodPost, "/auth/signup/verify", domain.CodeDTO{Code: code})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.signup.noPending", resp.Body.Error)
	})

	t.Run("login sets both auth cookies", func(t *testing.T) {
		other := newClient(t)
		resp := other.login(dto.Email, dto.Password)

		assert.Equal(t, http.StatusOK, resp.Status)
		assert.Equal(t, "auth.login.success", resp.Body.Message)
		assert.NotNil(t, other.cookie(api.AccessTokenCookieName))
		assert.NotNil(t, other.cookie(api.RefreshTokenCookieName))
	})

	t.Run("delete then login fails", func(t *testing.T) {
		blocked := c.do(http.MethodDelete, "/users/"+user.UUID, nil)
		require.Equal(t, http.StatusForbidden, blocked.Status)
		assert.Equal(t, "auth.stepUp.required", blocked.Body.Error)

		c.stepUp(dto.Email)

		deleted := c.do(http.MethodDelete, "/users/"+user.UUID, nil)
		assert.Equal(t, http.StatusNoContent, deleted.Status)
		cleared := map[string]bool{}
		for _, cookie := range deleted.Cookies {
			cleared[cookie.Name] = cookie.MaxAge < 0
		}
		assert.True(t, cleared["access_token"])
		assert.True(t, cleared["refresh_token"])

		resp := newClient(t).login(dto.Email, dto.Password)
		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.authenticate.invalidCredentials", resp.Body.Error)
	})
}
