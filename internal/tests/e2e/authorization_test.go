package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	userA, userB, admin := seedUser(t), seedUser(t), seedAdmin(t)
	clientA, clientAdmin := newClient(t), newClient(t)
	require.Equal(t, http.StatusOK, clientA.login(userA.Email, userA.Password).Status)
	require.Equal(t, http.StatusOK, clientAdmin.login(admin.Email, admin.Password).Status)

	t.Run("user cannot read another user", func(t *testing.T) {
		resp := clientA.do(http.MethodGet, "/users/"+userB.UUID, nil)

		assert.Equal(t, http.StatusForbidden, resp.Status)
		assert.Equal(t, "users.forbidden", resp.Body.Error)
	})

	t.Run("admin can read another user", func(t *testing.T) {
		resp := clientAdmin.do(http.MethodGet, "/users/"+userB.UUID, nil)

		require.Equal(t, http.StatusOK, resp.Status)
		var user domain.User
		require.NoError(t, json.Unmarshal(resp.Body.Data, &user))
		assert.Equal(t, userB.UUID, user.UUID)
	})

	t.Run("user list is admin only", func(t *testing.T) {
		forbidden := clientA.do(http.MethodGet, "/users", nil)
		assert.Equal(t, http.StatusForbidden, forbidden.Status)

		resp := clientAdmin.do(http.MethodGet, "/users?role=admin", nil)
		require.Equal(t, http.StatusOK, resp.Status)
		var users []domain.User
		require.NoError(t, json.Unmarshal(resp.Body.Data, &users))
		require.Len(t, users, 1)
		assert.Equal(t, domain.RoleAdmin, users[0].Role)
	})

	t.Run("audit logs are admin only", func(t *testing.T) {
		forbidden := clientA.do(http.MethodGet, "/audit-logs", nil)
		assert.Equal(t, http.StatusForbidden, forbidden.Status)

		resp := clientAdmin.do(http.MethodGet, "/audit-logs", nil)
		require.Equal(t, http.StatusOK, resp.Status)
		var logs []domain.AuditLog
		require.NoError(t, json.Unmarshal(resp.Body.Data, &logs))
		var logins int
		for _, entry := range logs {
			if entry.Action == domain.AuditActionLogin && entry.Status == domain.AuditStatusSuccess {
				logins++
			}
		}
		assert.Equal(t, 2, logins)
	})
}
