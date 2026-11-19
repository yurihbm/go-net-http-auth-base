package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const seedPassword = "password123"

type seededUser struct {
	UUID     string
	Email    string
	Password string
}

type client struct {
	t    *testing.T
	http *http.Client
	jar  *cookiejar.Jar
}

type response struct {
	Status int
	Body   api.ResponseBody[json.RawMessage]
	Raw    []byte

	Cookies []*http.Cookie
}

func truncateTables(t *testing.T, ctx context.Context, db *pgxpool.Pool) {
	t.Helper()
	tables := []string{"audit_logs", "email_send_limits", "pending_signups", "step_up_challenges", "user_sessions", "user_oauth_providers", "users"}
	for _, table := range tables {
		_, err := db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table))
		require.NoError(t, err, "truncate %s", table)
	}
}

func seedUser(t *testing.T) seededUser {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(seedPassword), bcrypt.MinCost)
	require.NoError(t, err)

	email := fmt.Sprintf("user-%s@example.com", uuid.NewString())
	created, err := repositories.NewUsersPostgresRepository(testDB).Create(context.Background(), domain.User{
		Name:         "Seeded User",
		Email:        email,
		PasswordHash: string(hash),
		Role:         domain.RoleUser,
	})
	require.NoError(t, err)

	return seededUser{UUID: created.UUID, Email: email, Password: seedPassword}
}

func seedAdmin(t *testing.T) seededUser {
	t.Helper()

	admin := seedUser(t)
	_, err := testDB.Exec(context.Background(), "UPDATE users SET role = 'admin' WHERE uuid = $1", admin.UUID)
	require.NoError(t, err)

	return admin
}

func newClient(t *testing.T) *client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &client{t: t, http: &http.Client{Jar: jar}, jar: jar}
}

func (c *client) do(method, path string, body any) response {
	c.t.Helper()

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		require.NoError(c.t, err)
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, serverURL+path, reader)
	require.NoError(c.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return send(c.t, c.http, req)
}

func send(t *testing.T, httpClient *http.Client, req *http.Request) response {
	t.Helper()

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	result := response{Status: resp.StatusCode, Raw: raw, Cookies: resp.Cookies()}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &result.Body)
	}
	return result
}

func (c *client) login(email, password string) response {
	c.t.Helper()

	return c.do(http.MethodPost, "/auth/login", domain.CredentialsLoginDTO{Email: email, Password: password})
}

func (c *client) cookie(name string) *http.Cookie {
	c.t.Helper()

	base, err := url.Parse(serverURL)
	require.NoError(c.t, err)

	for _, path := range []string{"/", api.RefreshTokenCookiePath} {
		u := *base
		u.Path = path
		for _, cookie := range c.jar.Cookies(&u) {
			if cookie.Name == name {
				return cookie
			}
		}
	}
	return nil
}

func (c *client) stepUp(email string) {
	c.t.Helper()

	requested := c.do(http.MethodPost, "/auth/step-up", nil)
	require.Equal(c.t, http.StatusAccepted, requested.Status)

	verified := c.do(http.MethodPost, "/auth/step-up/verify", domain.CodeDTO{Code: mailbox.otpCode(c.t, email)})
	require.Equal(c.t, http.StatusOK, verified.Status)
}
