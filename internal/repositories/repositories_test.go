package repositories_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
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
	tables := []string{"audit_logs", "email_send_limits", "password_resets", "pending_signups", "session_challenges", "user_sessions", "user_oauth_providers", "users"}
	for _, table := range tables {
		if _, err := db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)); err != nil {
			log.Fatalf("Failed to truncate table %s: %v", table, err)
		}
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func assertInternalError(t *testing.T, err error) {
	t.Helper()
	var internalErr *domain.InternalServerError
	assert.True(t, errors.As(err, &internalErr), "expected InternalServerError, got %v", err)
}
