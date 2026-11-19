package repositories

import (
	"context"
	"errors"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type EmailSendLimitsPostgresRepository struct {
	q *postgres.Queries
}

var _ domain.EmailSendLimiter = (*EmailSendLimitsPostgresRepository)(nil)

func NewEmailSendLimitsPostgresRepository(db postgres.DBTX) domain.EmailSendLimiter {
	return &EmailSendLimitsPostgresRepository{q: postgres.New(db)}
}

func (r *EmailSendLimitsPostgresRepository) ReserveSend(ctx context.Context, email string, cooldown time.Duration, window time.Duration, maxSends int) error {
	_, err := r.q.ReserveEmailSend(ctx, postgres.ReserveEmailSendParams{
		Email:      email,
		SendWindow: toInterval(window),
		Cooldown:   toInterval(cooldown),
		MaxSends:   int32(maxSends),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrEmailSendLimit
		}
		return domain.NewInternalServerError("auth.email.internalServerError", err)
	}
	return nil
}

func (r *EmailSendLimitsPostgresRepository) ReserveCodeGuess(ctx context.Context, email string, window time.Duration) error {
	_, err := r.q.ReserveEmailCodeGuess(ctx, postgres.ReserveEmailCodeGuessParams{
		Email:         email,
		FailureWindow: toInterval(window),
		MaxFailures:   int32(domain.EmailMaxCodeFailures),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrEmailCodeLocked
		}
		return domain.NewInternalServerError("auth.email.internalServerError", err)
	}
	return nil
}

func (r *EmailSendLimitsPostgresRepository) RefundCodeGuess(ctx context.Context, email string) error {
	if err := r.q.RefundEmailCodeGuess(ctx, email); err != nil {
		return domain.NewInternalServerError("auth.email.internalServerError", err)
	}
	return nil
}

func toInterval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
