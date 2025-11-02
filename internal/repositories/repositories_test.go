package repositories_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

var testDB *pgxpool.Pool

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
	if err := cmd.Run(); err != nil {
		log.Fatalf("Could not start testing database: %v", err)
	}
	log.Printf("Testing database started.")

	connStr := "postgres://testuser:testpassword@localhost:5433/testdb?sslmode=disable"
	// Migrate database using golang-migrate.
	cmd = exec.Command(
		"migrate",
		"-path",
		"./../../postgres/migrations",
		"-database",
		connStr,
		"up",
	)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Could not migrate the database: %v", err)
	}

	// Setup database connection.
	var err error
	testDB, err = pgxpool.New(ctx, connStr)
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
	tables := []string{"user_oauth_providers", "users"}
	for _, table := range tables {
		if _, err := db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)); err != nil {
			log.Fatalf("Failed to truncate table %s: %v", table, err)
		}
	}
}
