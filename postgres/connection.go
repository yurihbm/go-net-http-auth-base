package postgres

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

func NewConnection(ctx context.Context) *pgx.Conn {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found or failed to load")
	}

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
