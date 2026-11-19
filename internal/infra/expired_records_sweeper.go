package infra

import (
	"context"
	"log/slog"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgtype"
)

const expiredRecordsSweepBatchSize = 1000

type ExpiredRecordsSweeper struct {
	q *postgres.Queries
}

func NewExpiredRecordsSweeper(db postgres.DBTX) *ExpiredRecordsSweeper {
	return &ExpiredRecordsSweeper{q: postgres.New(db)}
}

func (s *ExpiredRecordsSweeper) RunMaintenance(ctx context.Context) error {
	return s.RunMaintenanceWithBatchSize(ctx, expiredRecordsSweepBatchSize)
}

func (s *ExpiredRecordsSweeper) RunMaintenanceWithBatchSize(ctx context.Context, batchSize int32) error {
	challenges, err := sweepInBatches(batchSize, func() (int64, error) {
		return s.q.DeleteExpiredStepUpChallengesBatch(ctx, batchSize)
	})
	if err != nil {
		return err
	}

	emailChangeChallenges, err := sweepInBatches(batchSize, func() (int64, error) {
		return s.q.DeleteExpiredEmailChangeChallengesBatch(ctx, batchSize)
	})
	if err != nil {
		return err
	}

	idleTimeout := pgtype.Interval{Microseconds: domain.TokenExpirationRefresh.Microseconds(), Valid: true}
	sessions, err := sweepInBatches(batchSize, func() (int64, error) {
		return s.q.DeleteExpiredUserSessionsBatch(ctx, postgres.DeleteExpiredUserSessionsBatchParams{
			IdleTimeout: idleTimeout,
			BatchSize:   batchSize,
		})
	})
	if err != nil {
		return err
	}

	pendingSignups, err := sweepInBatches(batchSize, func() (int64, error) {
		return s.q.DeleteExpiredPendingSignupsBatch(ctx, batchSize)
	})
	if err != nil {
		return err
	}

	emailSendLimits, err := sweepInBatches(batchSize, func() (int64, error) {
		return s.q.DeleteStaleEmailSendLimitsBatch(ctx, postgres.DeleteStaleEmailSendLimitsBatchParams{
			SendWindow:    pgtype.Interval{Microseconds: domain.EmailSendWindow.Microseconds(), Valid: true},
			FailureWindow: pgtype.Interval{Microseconds: domain.EmailCodeFailureWindow.Microseconds(), Valid: true},
			BatchSize:     batchSize,
		})
	})
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "expired records swept",
		"sessions", sessions,
		"step_up_challenges", challenges,
		"email_change_challenges", emailChangeChallenges,
		"pending_signups", pendingSignups,
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
