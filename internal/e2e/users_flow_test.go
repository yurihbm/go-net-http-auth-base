package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
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

	created := c.do(http.MethodPost, "/users", dto)
	require.Equal(t, http.StatusCreated, created.Status)
	assert.Equal(t, "user.create.success", created.Body.Message)
	var user domain.User
	require.NoError(t, json.Unmarshal(created.Body.Data, &user))
	assert.Equal(t, dto.Email, user.Email)

	t.Run("login sets both auth cookies", func(t *testing.T) {
		resp := c.login(dto.Email, dto.Password)

		assert.Equal(t, http.StatusOK, resp.Status)
		assert.Equal(t, "auth.login.success", resp.Body.Message)
		assert.NotNil(t, c.cookie(api.AccessTokenCookieName))
		assert.NotNil(t, c.cookie(api.RefreshTokenCookieName))
	})

	t.Run("me returns the signed up user", func(t *testing.T) {
		resp := c.do(http.MethodGet, "/users/me", nil)

		require.Equal(t, http.StatusOK, resp.Status)
		var me domain.User
		require.NoError(t, json.Unmarshal(resp.Body.Data, &me))
		assert.Equal(t, user, me)
	})

	t.Run("verification link verifies the email", func(t *testing.T) {
		token := mailbox.linkToken(t, dto.Email)

		resp := newClient(t).do(http.MethodPost, "/users/verify-email", domain.VerifyEmailDTO{Token: token})
		require.Equal(t, http.StatusOK, resp.Status)

		me := c.do(http.MethodGet, "/users/me", nil)
		var verified domain.User
		require.NoError(t, json.Unmarshal(me.Body.Data, &verified))
		assert.True(t, verified.EmailVerified)
	})

	t.Run("delete then login fails", func(t *testing.T) {
		blocked := c.do(http.MethodDelete, "/users/"+user.UUID, nil)
		require.Equal(t, http.StatusForbidden, blocked.Status)
		assert.Equal(t, "auth.stepUp.required", blocked.Body.Error)

		c.stepUp(dto.Email)

		deleted := c.do(http.MethodDelete, "/users/"+user.UUID, nil)
		assert.Equal(t, http.StatusNoContent, deleted.Status)

		resp := newClient(t).login(dto.Email, dto.Password)
		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.authenticate.invalidCredentials", resp.Body.Error)
	})
}
