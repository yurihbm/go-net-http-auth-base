package infra_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go-net-http-auth-base/internal/infra"
	"go-net-http-auth-base/postgres"
)

var testDB *pgxpool.Pool

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}

	ctx := context.Background()

	pool, cleanup, err := postgres.NewTestPool(ctx)
	if err != nil {
		log.Fatalf("Could not start infra testing database: %v", err)
	}
	testDB = pool

	code := m.Run()

	cleanup()

	os.Exit(code)
}

func TestAuditLogsPartitionManager_EnsurePartition(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	pm := infra.NewAuditLogsPartitionManager(testDB)

	t.Run("creates new partition", func(t *testing.T) {
		// Use a future date to avoid conflict with migration-created partitions
		futureDate := time.Date(2030, 1, 15, 0, 0, 0, 0, time.UTC)
		err := pm.EnsurePartition(ctx, futureDate)
		require.NoError(t, err)

		// Verify partition exists
		partitionName := "audit_logs_2030_01"
		var exists bool
		err = testDB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1)", partitionName).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "Partition %s should exist", partitionName)
	})

	t.Run("idempotent", func(t *testing.T) {
		futureDate := time.Date(2030, 2, 15, 0, 0, 0, 0, time.UTC)

		// First call
		err := pm.EnsurePartition(ctx, futureDate)
		require.NoError(t, err)

		// Second call should not fail
		err = pm.EnsurePartition(ctx, futureDate)
		require.NoError(t, err)
	})

}

func TestAuditLogsPartitionManager_RunMaintenance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	pm := infra.NewAuditLogsPartitionManager(testDB)

	t.Run("creates current and next month partitions", func(t *testing.T) {
		err := pm.RunMaintenance(ctx)
		require.NoError(t, err)

		now := time.Now().UTC()
		// Safe calculation for next month matching the fix in PartitionManager
		next := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)

		partitions := []string{
			fmt.Sprintf("audit_logs_%s", now.Format("2006_01")),
			fmt.Sprintf("audit_logs_%s", next.Format("2006_01")),
		}

		for _, p := range partitions {
			var exists bool
			err = testDB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1)", p).Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "Partition %s should exist", p)
		}
	})

	t.Run("RunMaintenanceAt handles end of month rollover correctly", func(t *testing.T) {
		// Simulate Jan 31st. +1 month should be Feb, not March.
		jan31 := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)

		err := pm.RunMaintenanceAt(ctx, jan31)
		require.NoError(t, err)

		// Expect Jan (current) and Feb (next)
		partitions := []string{
			"audit_logs_2026_01",
			"audit_logs_2026_02",
		}

		for _, p := range partitions {
			var exists bool
			err = testDB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1)", p).Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "Partition %s should exist (from Jan 31 simulation)", p)
		}
	})
}
