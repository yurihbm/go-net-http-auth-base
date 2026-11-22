package postgres

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func ToInterval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
