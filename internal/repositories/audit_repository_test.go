package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
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

		err := repo.Create(log)
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
		err := repo.Create(log)
		require.NoError(t, err)
	})
}
