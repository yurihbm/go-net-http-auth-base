package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"
)

func setupAuditRepoTest(t *testing.T) domain.AuditRepository {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	ctx := context.Background()
	repo := repositories.NewAuditPostgresRepository(testDB)
	require.NotNil(t, repo)

	truncateTables(ctx, testDB)

	return repo
}

func seedAuditLog(t *testing.T, repo domain.AuditRepository, log *domain.AuditLog) {
	t.Helper()
	err := repo.Create(context.Background(), log)
	require.NoError(t, err)
}

func TestAuditPostgresRepository_Create(t *testing.T) {
	repo := setupAuditRepoTest(t)

	actorUUID := uuid.New().String()
	requestUUID := uuid.New().String()
	resourceUUID := uuid.New().String()

	t.Run("success", func(t *testing.T) {
		log := &domain.AuditLog{
			ActorUUID:    &actorUUID,
			IPAddress:    "127.0.0.1",
			UserAgent:    "Go-Test-Agent",
			Action:       "USER_CREATE",
			ResourceType: "user",
			ResourceUUID: resourceUUID,
			RequestUUID:  requestUUID,
			Changes:      map[string]any{"foo": "bar"},
			Status:       "SUCCESS",
		}

		err := repo.Create(context.Background(), log)
		require.NoError(t, err)
	})

	t.Run("success minimal", func(t *testing.T) {
		log := &domain.AuditLog{
			IPAddress:    "127.0.0.1",
			UserAgent:    "Go-Test-Agent",
			Action:       "SYSTEM_EVENT",
			ResourceType: "system",
			ResourceUUID: uuid.New().String(),
			RequestUUID:  uuid.New().String(),
			Status:       "SUCCESS",
			// ActorUUID, Changes, FailureReason are nil/empty
		}
		err := repo.Create(context.Background(), log)
		require.NoError(t, err)
	})
}

func TestAuditPostgresRepository_List(t *testing.T) {
	repo := setupAuditRepoTest(t)
	ctx := context.Background()

	actorUUID := uuid.New().String()
	reason := "invalid credentials"

	// Seed a variety of audit logs for filtering tests
	seedAuditLog(t, repo, &domain.AuditLog{
		ActorUUID:    &actorUUID,
		IPAddress:    "127.0.0.1",
		UserAgent:    "agent-a",
		Action:       domain.AuditActionLogin,
		ResourceType: domain.AuditResourceAuth,
		ResourceUUID: uuid.New().String(),
		RequestUUID:  uuid.New().String(),
		Status:       domain.AuditStatusSuccess,
	})
	seedAuditLog(t, repo, &domain.AuditLog{
		IPAddress:     "10.0.0.1",
		UserAgent:     "agent-b",
		Action:        domain.AuditActionLogin,
		ResourceType:  domain.AuditResourceAuth,
		ResourceUUID:  uuid.New().String(),
		RequestUUID:   uuid.New().String(),
		Status:        domain.AuditStatusFailure,
		FailureReason: &reason,
	})
	seedAuditLog(t, repo, &domain.AuditLog{
		ActorUUID:    &actorUUID,
		IPAddress:    "10.0.0.2",
		UserAgent:    "agent-c",
		Action:       domain.AuditActionUserCreate,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: uuid.New().String(),
		RequestUUID:  uuid.New().String(),
		Status:       domain.AuditStatusSuccess,
		Changes:      map[string]any{"name": "Alice"},
	})

	t.Run("success - no filters returns all rows", func(t *testing.T) {
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{Limit: 10})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Len(t, logs, 3)

		// Verify fields are populated correctly for a log with ActorUUID and Changes
		var withActor *domain.AuditLog
		for i := range logs {
			if logs[i].Changes != nil {
				withActor = &logs[i]
				break
			}
		}
		require.NotNil(t, withActor)
		assert.NotEmpty(t, withActor.UUID)
		assert.Equal(t, &actorUUID, withActor.ActorUUID)
		assert.NotEmpty(t, withActor.RequestUUID)
		assert.NotZero(t, withActor.CreatedAt)
	})

	t.Run("filter by action", func(t *testing.T) {
		action := domain.AuditActionUserCreate
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:  10,
			Action: &action,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Len(t, logs, 1)
		assert.Equal(t, domain.AuditActionUserCreate, logs[0].Action)
	})

	t.Run("filter by resource_type", func(t *testing.T) {
		rt := domain.AuditResourceAuth
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:        10,
			ResourceType: &rt,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Len(t, logs, 2)
	})

	t.Run("filter by status success", func(t *testing.T) {
		status := domain.AuditStatusSuccess
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:  10,
			Status: &status,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Len(t, logs, 2)
		for _, l := range logs {
			assert.Equal(t, domain.AuditStatusSuccess, l.Status)
		}
	})

	t.Run("filter by status failure - maps FailureReason", func(t *testing.T) {
		status := domain.AuditStatusFailure
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:  10,
			Status: &status,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		require.Len(t, logs, 1)
		assert.Equal(t, domain.AuditStatusFailure, logs[0].Status)
		require.NotNil(t, logs[0].FailureReason)
		assert.Equal(t, reason, *logs[0].FailureReason)
		assert.Nil(t, logs[0].ActorUUID)
	})

	t.Run("filter by actor_uuid", func(t *testing.T) {
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:     10,
			ActorUUID: &actorUUID,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Len(t, logs, 2)
		for _, l := range logs {
			require.NotNil(t, l.ActorUUID)
			assert.Equal(t, actorUUID, *l.ActorUUID)
		}
	})

	t.Run("filter by date range - inclusive", func(t *testing.T) {
		start := time.Now().Add(-1 * time.Hour).Unix()
		end := time.Now().Add(1 * time.Hour).Unix()

		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:     10,
			StartDate: &start,
			EndDate:   &end,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Len(t, logs, 3)
	})

	t.Run("filter by date range - excludes all rows", func(t *testing.T) {
		past := time.Now().Add(-48 * time.Hour).Unix()
		pastEnd := time.Now().Add(-24 * time.Hour).Unix()

		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:     10,
			StartDate: &past,
			EndDate:   &pastEnd,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, logs)
	})

	t.Run("pagination - limit respected", func(t *testing.T) {
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{Limit: 2})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Len(t, logs, 2)
	})

	t.Run("pagination - cursor skips already seen rows", func(t *testing.T) {
		// Fetch the first page
		firstPage, _, err := repo.List(ctx, domain.ListAuditLogsDTO{Limit: 2})
		require.NoError(t, err)
		require.Len(t, firstPage, 2)

		cursor := firstPage[len(firstPage)-1].UUID

		// Fetch second page using cursor
		secondPage, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:  2,
			Cursor: &cursor,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Len(t, secondPage, 1)

		// Ensure no overlap
		firstIDs := map[string]bool{firstPage[0].UUID: true, firstPage[1].UUID: true}
		for _, l := range secondPage {
			assert.False(t, firstIDs[l.UUID], "cursor-paginated result should not overlap with first page")
		}
	})

	t.Run("invalid actor_uuid returns validation error", func(t *testing.T) {
		invalid := "not-a-uuid"
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:     10,
			ActorUUID: &invalid,
		})

		require.Error(t, err)
		assert.Nil(t, logs)
		assert.Zero(t, total)
		var validationErr *domain.ValidationError
		assert.ErrorAs(t, err, &validationErr)
	})

	t.Run("invalid cursor returns validation error", func(t *testing.T) {
		invalid := "not-a-uuid"
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:  10,
			Cursor: &invalid,
		})

		require.Error(t, err)
		assert.Nil(t, logs)
		assert.Zero(t, total)
		var validationErr *domain.ValidationError
		assert.ErrorAs(t, err, &validationErr)
	})

	t.Run("no matching results returns empty slice", func(t *testing.T) {
		action := "NONEXISTENT_ACTION"
		logs, total, err := repo.List(ctx, domain.ListAuditLogsDTO{
			Limit:  10,
			Action: &action,
		})

		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, logs)
	})
}
