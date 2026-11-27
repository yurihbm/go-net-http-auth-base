package e2e_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"go-net-http-auth-base/internal/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	t.Run("refresh rotates tokens and invalidates the old refresh token", func(t *testing.T) {
		truncateTables(t, context.Background(), testDB)
		user := seedUser(t)
		c := newClient(t)
		require.Equal(t, http.StatusOK, c.login(user.Email, user.Password).Status)
		oldRefresh := c.cookie(api.RefreshTokenCookieName)
		require.NotNil(t, oldRefresh)

		resp := c.do(http.MethodPost, "/auth/refresh", nil)

		require.Equal(t, http.StatusOK, resp.Status)
		assert.Equal(t, "auth.refresh.success", resp.Body.Message)
		newRefresh := c.cookie(api.RefreshTokenCookieName)
		require.NotNil(t, newRefresh)
		assert.NotEqual(t, oldRefresh.Value, newRefresh.Value)
		assert.Equal(t, http.StatusOK, c.do(http.MethodGet, "/users/me", nil).Status)

		stale := refreshWithToken(t, oldRefresh.Value)
		assert.Equal(t, http.StatusUnauthorized, stale.Status)
	})

	t.Run("logout only ends the current device session", func(t *testing.T) {
		truncateTables(t, context.Background(), testDB)
		user := seedUser(t)
		phone, laptop := newClient(t), newClient(t)
		require.Equal(t, http.StatusOK, phone.login(user.Email, user.Password).Status)
		require.Equal(t, http.StatusOK, laptop.login(user.Email, user.Password).Status)
		phoneRefresh := phone.cookie(api.RefreshTokenCookieName)
		require.NotNil(t, phoneRefresh)

		logout := phone.do(http.MethodPost, "/auth/logout", nil)

		require.Equal(t, http.StatusOK, logout.Status)
		assert.Equal(t, "auth.logout.success", logout.Body.Message)
		assert.Equal(t, http.StatusUnauthorized, refreshWithToken(t, phoneRefresh.Value).Status)
		assert.Equal(t, http.StatusOK, laptop.do(http.MethodGet, "/users/me", nil).Status)
		assert.Equal(t, http.StatusOK, laptop.do(http.MethodPost, "/auth/refresh", nil).Status)
	})
}

func TestConcurrentRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)
	user := seedUser(t)
	c := newClient(t)
	require.Equal(t, http.StatusOK, c.login(user.Email, user.Password).Status)
	refresh := c.cookie(api.RefreshTokenCookieName)
	require.NotNil(t, refresh)

	const attempts = 10
	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		statuses = make([]int, attempts)
		winners  = make([]*http.Cookie, attempts)
	)
	for i := range attempts {
		wg.Go(func() {
			<-start
			req, err := http.NewRequest(http.MethodPost, serverURL+"/auth/refresh", nil)
			if !assert.NoError(t, err) {
				return
			}
			req.AddCookie(&http.Cookie{Name: api.RefreshTokenCookieName, Value: refresh.Value})
			resp, err := http.DefaultClient.Do(req)
			if !assert.NoError(t, err) {
				return
			}
			defer func() { assert.NoError(t, resp.Body.Close()) }()
			statuses[i] = resp.StatusCode
			for _, cookie := range resp.Cookies() {
				if cookie.Name == api.RefreshTokenCookieName {
					winners[i] = cookie
				}
			}
		})
	}
	close(start)
	wg.Wait()

	var ok, unauthorized int
	var winnerToken string
	for i, status := range statuses {
		switch status {
		case http.StatusOK:
			ok++
			require.NotNil(t, winners[i])
			winnerToken = winners[i].Value
		case http.StatusUnauthorized:
			unauthorized++
		}
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, attempts-1, unauthorized)

	require.NotEmpty(t, winnerToken)
	assert.Equal(t, http.StatusUnauthorized, refreshWithToken(t, winnerToken).Status)
}

func refreshWithToken(t *testing.T, token string) response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, serverURL+"/auth/refresh", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: api.RefreshTokenCookieName, Value: token})

	return send(t, &http.Client{}, req)
}
