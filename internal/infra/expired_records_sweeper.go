package infra

import (
	"context"
	"fmt"
	"log/slog"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	expiredRecordsSweepBatchSize = 1000
	// expiredRecordsSweepLockID is a unique advisory lock ID for the expired
	// records sweep. Generated arbitrarily to avoid collision with other locks.
	expiredRecordsSweepLockID = 5129384756
)

type ExpiredRecordsSweeper struct {
	pool *pgxpool.Pool
}

func NewExpiredRecordsSweeper(pool *pgxpool.Pool) *ExpiredRecordsSweeper {
	return &ExpiredRecordsSweeper{pool: pool}
}

func (s *ExpiredRecordsSweeper) RunMaintenance(ctx context.Context) error {
	return s.RunMaintenanceWithBatchSize(ctx, expiredRecordsSweepBatchSize)
}

// RunMaintenanceWithBatchSize sweeps expired records unless another instance is
// already sweeping. It holds one connection for the whole run: the session-level
// advisory lock and every delete batch use it, so each batch still commits on
// its own and the sweep never needs a second pool connection.
func (s *ExpiredRecordsSweeper) RunMaintenanceWithBatchSize(ctx context.Context, batchSize int32) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", expiredRecordsSweepLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("failed to acquire sweep lock: %w", err)
	}
	if !acquired {
		slog.InfoContext(ctx, "expired records sweep skipped, another instance holds the lock")
		return nil
	}
	defer func() {
		// A fresh context lets the unlock run even when ctx was canceled; if it
		// still fails, closing the connection releases the session lock.
		if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", expiredRecordsSweepLockID); err != nil {
			slog.ErrorContext(ctx, "failed to release sweep lock", "error", err)
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
		}
	}()

	return s.sweep(ctx, postgres.New(conn), batchSize)
}

func (s *ExpiredRecordsSweeper) sweep(ctx context.Context, q *postgres.Queries, batchSize int32) error {
	challenges, err := sweepInBatches(batchSize, func() (int64, error) {
		return q.DeleteExpiredSessionChallengesBatch(ctx, batchSize)
	})
	if err != nil {
		return err
	}

	idleTimeout := postgres.ToInterval(domain.TokenExpirationRefresh)
	sessions, err := sweepInBatches(batchSize, func() (int64, error) {
		return q.DeleteExpiredUserSessionsBatch(ctx, postgres.DeleteExpiredUserSessionsBatchParams{
			IdleTimeout: idleTimeout,
			BatchSize:   batchSize,
		})
	})
	if err != nil {
		return err
	}

	pendingSignups, err := sweepInBatches(batchSize, func() (int64, error) {
		return q.DeleteExpiredPendingSignupsBatch(ctx, batchSize)
	})
	if err != nil {
		return err
	}

	passwordResets, err := sweepInBatches(batchSize, func() (int64, error) {
		return q.DeleteExpiredPasswordResetsBatch(ctx, batchSize)
	})
	if err != nil {
		return err
	}

	emailSendLimits, err := sweepInBatches(batchSize, func() (int64, error) {
		return q.DeleteStaleEmailSendLimitsBatch(ctx, postgres.DeleteStaleEmailSendLimitsBatchParams{
			SendWindow:    postgres.ToInterval(domain.EmailSendWindow),
			FailureWindow: postgres.ToInterval(domain.EmailCodeFailureWindow),
			BatchSize:     batchSize,
		})
	})
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "expired records swept",
		"sessions", sessions,
		"session_challenges", challenges,
		"pending_signups", pendingSignups,
		"password_resets", passwordResets,
		"email_send_limits", emailSendLimits,
	)
	return nil
}

func sweepInBatches(batchSize int32, deleteBatch func() (int64, error)) (int64, error) {
	var total int64
	for {
		n, err := deleteBatch()
		if err != nil {
			return total, err
		}
		total += n
		if n < int64(batchSize) {
			return total, nil
		}
	}
}
