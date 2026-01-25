package repositories

import (
	"errors"
	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func parseUUID(uuidStr string, errorMessage string) (*pgtype.UUID, error) {
	parsedUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, domain.NewValidationError(
			errorMessage,
			map[string]string{"uuid": err.Error()},
		)
	}

	return &pgtype.UUID{Bytes: [16]byte(parsedUUID), Valid: true}, nil
}

func isNoRowsError(err error, notFoundMessage string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NewNotFoundError(notFoundMessage)
	}
	return nil
}

func isConflictError(err error, conflictMessage string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23505" {
			return domain.NewConflictError(conflictMessage)
		}
	}

	return nil
}

func isForeignKeyViolationError(err error, message string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23503" {
			return domain.NewNotFoundError(message)
		}
	}
	return nil
}
