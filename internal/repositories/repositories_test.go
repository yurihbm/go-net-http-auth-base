package repositories_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"

	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

var testDB *pgxpool.Pool

const testConnStr = "postgres://testuser:testpassword@localhost:5433/testdb?sslmode=disable"

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start docker container.
	cmd := exec.Command(
		"docker",
		"compose",
		"-f",
		"../../docker/docker-compose.test.yaml",
		"up",
		"-d",
		"--wait",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("Could not start testing database: %v\n%s", err, out)
	}
	log.Printf("Testing database started.")

	// Migrate database using golang-migrate.
	cmd = exec.Command(
		"migrate",
		"-path",
		"./../../postgres/migrations",
		"-database",
		testConnStr,
		"up",
	)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Could not migrate the database: %v", err)
	}

	// Setup database connection using the shared postgres package helper so
	// that production pool configuration logic is exercised during tests.
	os.Setenv("DATABASE_URL", testConnStr)
	var err error
	testDB, err = postgres.NewConnectionPool(ctx)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	// Run tests.
	code := m.Run()

	// Teardown.
	testDB.Close()
	cmd = exec.Command(
		"docker",
		"compose",
		"-f",
		"../../docker/docker-compose.test.yaml",
		"down",
	)
	if err := cmd.Run(); err != nil {
		log.Printf("could not stop docker-compose: %v", err)
	}

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
