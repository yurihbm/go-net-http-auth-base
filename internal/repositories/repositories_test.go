package repositories_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
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
		log.Fatalf("Could not start testing database: %v", err)
	}
	testDB = pool

	code := m.Run()

	cleanup()

	os.Exit(code)
}

func truncateTables(ctx context.Context, db *pgxpool.Pool) {
	// Add all tables you want to clean up between tests
	tables := []string{"audit_logs", "user_oauth_providers", "users"}
	for _, table := range tables {
		if _, err := db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)); err != nil {
			log.Fatalf("Failed to truncate table %s: %v", table, err)
		}
	}
}
