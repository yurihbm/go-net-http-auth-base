package postgres

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func NewConnection(ctx context.Context) *pgx.Conn {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not set in environment")
	}

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}

	return conn
}
