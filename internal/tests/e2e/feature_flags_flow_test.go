package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFeatureFlagsAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	truncateTables(t, context.Background(), testDB)

	user, admin := seedUser(t), seedAdmin(t)
	anonymous, userClient, adminClient := newClient(t), newClient(t), newClient(t)
	require.Equal(t, http.StatusOK, userClient.login(user.Email, user.Password).Status)
	require.Equal(t, http.StatusOK, adminClient.login(admin.Email, admin.Password).Status)

	t.Run("routes require an admin", func(t *testing.T) {
		body := domain.CreateFeatureFlagDTO{Key: "new-dashboard"}

		assert.Equal(t, http.StatusUnauthorized, anonymous.do(http.MethodPost, "/feature-flags", body).Status)
		assert.Equal(t, http.StatusForbidden, userClient.do(http.MethodPost, "/feature-flags", body).Status)
		assert.Equal(t, http.StatusForbidden, userClient.do(http.MethodGet, "/feature-flags", nil).Status)
	})

	var flag domain.FeatureFlag
	flagPath := func() string { return "/feature-flags/" + flag.UUID }

	t.Run("create", func(t *testing.T) {
		created := adminClient.do(http.MethodPost, "/feature-flags", domain.CreateFeatureFlagDTO{
			Key:         "new-dashboard",
			Description: "Redesigned dashboard",
		})

		require.Equal(t, http.StatusCreated, created.Status)
		require.NoError(t, json.Unmarshal(created.Body.Data, &flag))
		assert.Equal(t, "new-dashboard", flag.Key)
		assert.False(t, flag.EnabledGlobally)

		duplicate := adminClient.do(http.MethodPost, "/feature-flags", domain.CreateFeatureFlagDTO{Key: "new-dashboard"})
		assert.Equal(t, http.StatusConflict, duplicate.Status)
		assert.Equal(t, "featureFlags.key.conflict", duplicate.Body.Error)

		invalid := adminClient.do(http.MethodPost, "/feature-flags", map[string]any{"key": "Not Valid"})
		assert.Equal(t, http.StatusBadRequest, invalid.Status)
		assert.Equal(t, "request.validationFailed", invalid.Body.Error)
	})

	t.Run("allow-list", func(t *testing.T) {
		userPath := flagPath() + "/users/" + user.UUID

		require.Equal(t, http.StatusNoContent, adminClient.do(http.MethodPut, userPath, nil).Status)
		assert.Equal(t, http.StatusNoContent, adminClient.do(http.MethodPut, userPath, nil).Status, "adding twice is not an error")

		missingUser := adminClient.do(http.MethodPut, flagPath()+"/users/"+uuid.NewString(), nil)
		assert.Equal(t, http.StatusNotFound, missingUser.Status)
		assert.Equal(t, "users.notFound", missingUser.Body.Error)

		details := adminClient.do(http.MethodGet, flagPath(), nil)
		require.Equal(t, http.StatusOK, details.Status)
		var got domain.FeatureFlagDetails
		require.NoError(t, json.Unmarshal(details.Body.Data, &got))
		assert.Equal(t, []string{user.UUID}, got.UserUUIDs)

		require.Equal(t, http.StatusNoContent, adminClient.do(http.MethodDelete, userPath, nil).Status)
		notListed := adminClient.do(http.MethodDelete, userPath, nil)
		assert.Equal(t, http.StatusNotFound, notListed.Status)
		assert.Equal(t, "featureFlags.users.notFound", notListed.Body.Error)
	})

	t.Run("update and list", func(t *testing.T) {
		enabled := true
		updated := adminClient.do(http.MethodPatch, flagPath(), domain.UpdateFeatureFlagDTO{EnabledGlobally: &enabled})
		require.Equal(t, http.StatusOK, updated.Status)
		var got domain.FeatureFlag
		require.NoError(t, json.Unmarshal(updated.Body.Data, &got))
		assert.True(t, got.EnabledGlobally)
		assert.Equal(t, "Redesigned dashboard", got.Description)

		list := adminClient.do(http.MethodGet, "/feature-flags", nil)
		require.Equal(t, http.StatusOK, list.Status)
		var flags []domain.FeatureFlag
		require.NoError(t, json.Unmarshal(list.Body.Data, &flags))
		require.Len(t, flags, 1)
		assert.Equal(t, flag.UUID, flags[0].UUID)
	})

	t.Run("delete removes the flag with its allow-list", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, adminClient.do(http.MethodPut, flagPath()+"/users/"+user.UUID, nil).Status)

		require.Equal(t, http.StatusNoContent, adminClient.do(http.MethodDelete, flagPath(), nil).Status)

		missing := adminClient.do(http.MethodGet, flagPath(), nil)
		assert.Equal(t, http.StatusNotFound, missing.Status)
		assert.Equal(t, "featureFlags.notFound", missing.Body.Error)
		var rows int
		require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM feature_flag_users").Scan(&rows))
		assert.Zero(t, rows)
	})

	t.Run("changes are audited", func(t *testing.T) {
		resp := adminClient.do(http.MethodGet, "/audit-logs?resource_type="+domain.AuditResourceFeatureFlag+"&limit=100", nil)
		require.Equal(t, http.StatusOK, resp.Status)
		var logs []domain.AuditLog
		require.NoError(t, json.Unmarshal(resp.Body.Data, &logs))

		type outcome struct{ action, status string }
		seen := map[outcome]int{}
		for _, entry := range logs {
			seen[outcome{entry.Action, entry.Status}]++
		}
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagCreate, domain.AuditStatusSuccess}])
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagCreate, domain.AuditStatusFailure}])
		assert.Equal(t, 3, seen[outcome{domain.AuditActionFeatureFlagUserAdd, domain.AuditStatusSuccess}])
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagUserAdd, domain.AuditStatusFailure}])
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagUserRemove, domain.AuditStatusSuccess}])
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagUserRemove, domain.AuditStatusFailure}])
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagUpdate, domain.AuditStatusSuccess}])
		assert.Equal(t, 1, seen[outcome{domain.AuditActionFeatureFlagDelete, domain.AuditStatusSuccess}])
	})
}
