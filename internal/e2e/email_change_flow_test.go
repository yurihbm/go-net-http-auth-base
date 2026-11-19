package e2e_test

import (
	"context"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailChangeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	user := seedUser(t)
	newEmail := "changed-" + user.Email
	phone, laptop := newClient(t), newClient(t)
	require.Equal(t, http.StatusOK, phone.login(user.Email, user.Password).Status)
	require.Equal(t, http.StatusOK, laptop.login(user.Email, user.Password).Status)

	t.Run("email change requires step-up", func(t *testing.T) {
		resp := phone.do(http.MethodPost, "/users/me/email", domain.RequestEmailChangeDTO{Email: newEmail})

		assert.Equal(t, http.StatusForbidden, resp.Status)
		assert.Equal(t, "auth.stepUp.required", resp.Body.Error)
	})

	t.Run("step-up rejects a wrong code and accepts the emailed one", func(t *testing.T) {
		requested := phone.do(http.MethodPost, "/auth/step-up", nil)
		require.Equal(t, http.StatusAccepted, requested.Status)

		code := mailbox.otpCode(t, user.Email)
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		rejected := phone.do(http.MethodPost, "/auth/step-up/verify", domain.CodeDTO{Code: wrong})
		assert.Equal(t, http.StatusUnauthorized, rejected.Status)

		accepted := phone.do(http.MethodPost, "/auth/step-up/verify", domain.CodeDTO{Code: code})
		assert.Equal(t, http.StatusOK, accepted.Status)
	})

	t.Run("request sends the code to the new address", func(t *testing.T) {
		resp := phone.do(http.MethodPost, "/users/me/email", domain.RequestEmailChangeDTO{Email: newEmail})

		require.Equal(t, http.StatusAccepted, resp.Status)
		assert.Len(t, mailbox.otpCode(t, newEmail), 6)
	})

	t.Run("a second device cannot confirm with the code", func(t *testing.T) {
		resp := laptop.do(http.MethodPost, "/users/me/email/confirm", domain.CodeDTO{Code: mailbox.otpCode(t, newEmail)})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "users.emailChange.noChallenge", resp.Body.Error)
	})

	t.Run("a wrong code is rejected", func(t *testing.T) {
		wrong := "000000"
		if mailbox.otpCode(t, newEmail) == wrong {
			wrong = "111111"
		}

		resp := phone.do(http.MethodPost, "/users/me/email/confirm", domain.CodeDTO{Code: wrong})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "users.emailChange.invalidCode", resp.Body.Error)
	})

	code := mailbox.otpCode(t, newEmail)
	t.Run("confirm in the requesting session changes the email and signs out every device", func(t *testing.T) {
		resp := phone.do(http.MethodPost, "/users/me/email/confirm", domain.CodeDTO{Code: code})

		require.Equal(t, http.StatusOK, resp.Status)
		cleared := map[string]bool{}
		for _, cookie := range resp.Cookies {
			if cookie.MaxAge < 0 {
				cleared[cookie.Name] = true
			}
		}
		assert.True(t, cleared[api.AccessTokenCookieName])
		assert.True(t, cleared[api.RefreshTokenCookieName])
		assert.Equal(t, http.StatusUnauthorized, phone.do(http.MethodPost, "/auth/refresh", nil).Status)
		assert.Equal(t, http.StatusUnauthorized, laptop.do(http.MethodPost, "/auth/refresh", nil).Status)
	})

	t.Run("the used code cannot be replayed", func(t *testing.T) {
		device := newClient(t)
		require.Equal(t, http.StatusOK, device.login(newEmail, user.Password).Status)

		resp := device.do(http.MethodPost, "/users/me/email/confirm", domain.CodeDTO{Code: code})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "users.emailChange.noChallenge", resp.Body.Error)
	})

	t.Run("another change right after is locked", func(t *testing.T) {
		device := newClient(t)
		require.Equal(t, http.StatusOK, device.login(newEmail, user.Password).Status)
		device.stepUp(newEmail)

		resp := device.do(http.MethodPost, "/users/me/email", domain.RequestEmailChangeDTO{Email: "again-" + user.Email})

		assert.Equal(t, http.StatusConflict, resp.Status)
		assert.Equal(t, "users.emailChange.locked", resp.Body.Error)
	})

	t.Run("undo link reverts the email and signs out every device", func(t *testing.T) {
		device := newClient(t)
		require.Equal(t, http.StatusOK, device.login(newEmail, user.Password).Status)
		revertToken := mailbox.linkToken(t, user.Email)

		resp := newClient(t).do(http.MethodPost, "/users/revert-email-change", domain.RevertEmailChangeDTO{Token: revertToken})

		require.Equal(t, http.StatusOK, resp.Status)
		assert.Equal(t, http.StatusUnauthorized, device.do(http.MethodPost, "/auth/refresh", nil).Status)
		assert.Equal(t, http.StatusUnauthorized, newClient(t).login(newEmail, user.Password).Status)
		assert.Equal(t, http.StatusOK, newClient(t).login(user.Email, user.Password).Status)

		replay := newClient(t).do(http.MethodPost, "/users/revert-email-change", domain.RevertEmailChangeDTO{Token: revertToken})
		assert.Equal(t, http.StatusUnauthorized, replay.Status)
	})
}

func TestLogoutOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	user := seedUser(t)
	deviceA, deviceB := newClient(t), newClient(t)
	require.Equal(t, http.StatusOK, deviceA.login(user.Email, user.Password).Status)
	require.Equal(t, http.StatusOK, deviceB.login(user.Email, user.Password).Status)

	t.Run("logout-others keeps only the current session", func(t *testing.T) {
		resp := deviceA.do(http.MethodPost, "/auth/logout-others", nil)

		assert.Equal(t, http.StatusNoContent, resp.Status)
		assert.Equal(t, http.StatusUnauthorized, deviceB.do(http.MethodPost, "/auth/refresh", nil).Status)
		assert.Equal(t, http.StatusOK, deviceA.do(http.MethodPost, "/auth/refresh", nil).Status)
	})
}
