package infra

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
)

const (
	// unique lock ID for audit logs partition creation
	// Generated arbitrarily to avoid collision with other locks
	auditLogsPartitionLockID = 8374928374
)

type Transactioner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

type AuditLogsPartitionManager struct {
	db postgres.DBTX
}

func NewAuditLogsPartitionManager(db postgres.DBTX) *AuditLogsPartitionManager {
	return &AuditLogsPartitionManager{db: db}
}

// EnsurePartition ensures that a partition exists for the given date's month.
// It uses PostgreSQL advisory locks to ensure safe concurrent execution.
func (pm *AuditLogsPartitionManager) EnsurePartition(ctx context.Context, date time.Time) error {
	txer, ok := pm.db.(Transactioner)
	if !ok {
		return fmt.Errorf("database connection does not support transactions")
	}

	tx, err := txer.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// 1. Acquire Transaction-level Advisory Lock
	// This lock will be automatically released when the transaction ends.
	_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLogsPartitionLockID)
	if err != nil {
		return fmt.Errorf("failed to acquire partition lock: %w", err)
	}

	// 2. Calculate partition details
	// Partition name: audit_logs_YYYY_MM
	monthStr := date.Format("2006_01")
	partitionName := fmt.Sprintf("audit_logs_%s", monthStr)

	// Start of month: YYYY-MM-01
	startOfMonth := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, time.UTC)
	startStr := startOfMonth.Format("2006-01-02")

	// Start of next month: (YYYY-MM + 1 month)-01
	nextMonth := startOfMonth.AddDate(0, 1, 0)
	endStr := nextMonth.Format("2006-01-02")

	// 3. Check if partition exists
	var exists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1)"
	err = tx.QueryRow(ctx, checkQuery, partitionName).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check partition existence: %w", err)
	}

	if exists {
		return tx.Commit(ctx)
	}

	// 4. Create Partition
	slog.Info("Creating audit log partition", "partition", partitionName, "start", startStr, "end", endStr)
	createAuthQuery := fmt.Sprintf(
		"CREATE TABLE %s PARTITION OF audit_logs FOR VALUES FROM ('%s') TO ('%s')",
		partitionName, startStr, endStr,
	)

	_, err = tx.Exec(ctx, createAuthQuery)
	if err != nil {
		return fmt.Errorf("failed to create partition %s: %w", partitionName, err)
	}

	return tx.Commit(ctx)
}

// RunMaintenance checks for current and next month partitions using current time
func (pm *AuditLogsPartitionManager) RunMaintenance(ctx context.Context) error {
	return pm.RunMaintenanceAt(ctx, time.Now().UTC())
}

// RunMaintenanceAt checks for partitions relative to the provided time.
// It normalizes to the start of the month to ensure safe date arithmetic.
func (pm *AuditLogsPartitionManager) RunMaintenanceAt(ctx context.Context, now time.Time) error {
	// Normalize to start of current month to avoid edge cases (e.g., Jan 31 + 1 month = Mar 3)
	currentMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	if err := pm.EnsurePartition(ctx, currentMonth); err != nil {
		return err
	}

	// Ensure next month
	nextMonth := currentMonth.AddDate(0, 1, 0)
	if err := pm.EnsurePartition(ctx, nextMonth); err != nil {
		return err
	}

	return nil
}