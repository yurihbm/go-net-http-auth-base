package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const newPassword = "brand-new-password"

func TestPasswordResetFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	user := seedUser(t)
	phone := newClient(t)
	require.Equal(t, http.StatusOK, phone.login(user.Email, user.Password).Status)
	browser := newClient(t)

	t.Run("a reset code only works in the browser that requested it", func(t *testing.T) {
		resp := browser.do(http.MethodPost, "/auth/password/forgot", domain.ForgotPasswordDTO{Email: user.Email})
		require.Equal(t, http.StatusAccepted, resp.Status)
		require.NotNil(t, browser.cookie("password_reset"))

		other := newClient(t)
		rejected := other.do(http.MethodPost, "/auth/password/reset", domain.ResetPasswordDTO{Code: mailbox.otpCode(t, user.Email), Password: newPassword})

		assert.Equal(t, http.StatusUnauthorized, rejected.Status)
		assert.Equal(t, "auth.passwordReset.invalidCode", rejected.Body.Error)
	})

	t.Run("a wrong code is rejected", func(t *testing.T) {
		wrong := "000000"
		if mailbox.otpCode(t, user.Email) == wrong {
			wrong = "111111"
		}

		resp := browser.do(http.MethodPost, "/auth/password/reset", domain.ResetPasswordDTO{Code: wrong, Password: newPassword})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.passwordReset.invalidCode", resp.Body.Error)
	})

	code := mailbox.otpCode(t, user.Email)
	t.Run("the emailed code sets the password, signs out every device and does not log in", func(t *testing.T) {
		resp := browser.do(http.MethodPost, "/auth/password/reset", domain.ResetPasswordDTO{Code: code, Password: newPassword})

		require.Equal(t, http.StatusOK, resp.Status)
		assert.Equal(t, "auth.passwordReset.success", resp.Body.Message)
		assert.Nil(t, browser.cookie("access_token"))
		assert.Equal(t, http.StatusUnauthorized, browser.do(http.MethodGet, "/users/me", nil).Status)
		assert.Contains(t, mailbox.last(t, user.Email).Subject, "password was changed")
	})

	t.Run("the old refresh token is rejected", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, phone.do(http.MethodPost, "/auth/refresh", nil).Status)
	})

	t.Run("the old password no longer logs in and the new one does", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, newClient(t).login(user.Email, user.Password).Status)
		assert.Equal(t, http.StatusOK, newClient(t).login(user.Email, newPassword).Status)
	})

	t.Run("the used code cannot be replayed", func(t *testing.T) {
		resp := browser.do(http.MethodPost, "/auth/password/reset", domain.ResetPasswordDTO{Code: code, Password: "another-password"})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.passwordReset.invalidCode", resp.Body.Error)
	})
}

func TestPasswordResetUnknownEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	email := fmt.Sprintf("ghost-%s@example.com", uuid.Must(uuid.NewV7()).String())
	browser := newClient(t)

	t.Run("answers like a known address, with a cookie and no email", func(t *testing.T) {
		resp := browser.do(http.MethodPost, "/auth/password/forgot", domain.ForgotPasswordDTO{Email: email})

		require.Equal(t, http.StatusAccepted, resp.Status)
		assert.Equal(t, "auth.passwordReset.requested", resp.Body.Message)
		require.NotNil(t, browser.cookie("password_reset"))
		mailbox.none(t, email)
	})

	t.Run("any code is rejected", func(t *testing.T) {
		resp := browser.do(http.MethodPost, "/auth/password/reset", domain.ResetPasswordDTO{Code: "123456", Password: newPassword})

		assert.Equal(t, http.StatusUnauthorized, resp.Status)
		assert.Equal(t, "auth.passwordReset.invalidCode", resp.Body.Error)
	})

	t.Run("the send limit applies to unknown addresses too", func(t *testing.T) {
		resp := browser.do(http.MethodPost, "/auth/password/forgot", domain.ForgotPasswordDTO{Email: email})

		assert.Equal(t, http.StatusTooManyRequests, resp.Status)
		assert.Equal(t, "auth.email.sendLimit", resp.Body.Error)
	})
}

func TestPasswordChangeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	user := seedUser(t)
	phone, laptop := newClient(t), newClient(t)
	require.Equal(t, http.StatusOK, phone.login(user.Email, user.Password).Status)
	require.Equal(t, http.StatusOK, laptop.login(user.Email, user.Password).Status)

	t.Run("requires step-up", func(t *testing.T) {
		resp := phone.do(http.MethodPost, "/users/me/password", domain.ChangePasswordDTO{NewPassword: newPassword})

		assert.Equal(t, http.StatusForbidden, resp.Status)
		assert.Equal(t, "auth.stepUp.required", resp.Body.Error)
	})

	t.Run("after step-up it changes the password and signs out only the other devices", func(t *testing.T) {
		phone.stepUp(user.Email)

		resp := phone.do(http.MethodPost, "/users/me/password", domain.ChangePasswordDTO{NewPassword: newPassword})

		require.Equal(t, http.StatusNoContent, resp.Status)
		assert.Equal(t, http.StatusOK, phone.do(http.MethodGet, "/users/me", nil).Status)
		assert.Equal(t, http.StatusOK, phone.do(http.MethodPost, "/auth/refresh", nil).Status)
		assert.Equal(t, http.StatusUnauthorized, laptop.do(http.MethodPost, "/auth/refresh", nil).Status)
		assert.Contains(t, mailbox.last(t, user.Email).Subject, "password was changed")
	})

	t.Run("the new password logs in and the old one does not", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, newClient(t).login(user.Email, user.Password).Status)
		assert.Equal(t, http.StatusOK, newClient(t).login(user.Email, newPassword).Status)
	})
}
