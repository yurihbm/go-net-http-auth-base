package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"

	"github.com/testcontainers/testcontainers-go"
	testContainerPg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testDBName     = "testdb"
	testDBUser     = "testuser"
	testDBPassword = "testpassword"

	defaultTestDBPortStart = 15432
	defaultTestDBPortEnd   = 15499
)

// NewTestPool starts an ephemeral PostgreSQL container, applies all migrations,
// and returns a connection pool ready for integration tests.
//
// The returned cleanup function closes the pool and terminates the container.
// Callers are responsible for invoking it (typically deferred in TestMain right
// after m.Run()).
//
//	func TestMain(m *testing.M) {
//	    ctx := context.Background()
//	    pool, cleanup, err := postgres.NewTestPool(ctx)
//	    if err != nil {
//	        log.Fatalf("could not start test database: %v", err)
//	    }
//	    testDB = pool
//	    code := m.Run()
//	    cleanup()
//	    os.Exit(code)
//	}
func NewTestPool(ctx context.Context) (*pgxpool.Pool, func(), error) {
	pgContainer, err := runTestPostgresContainer(ctx)
	if err != nil {
		return nil, nil, err
	}

	terminate := func() {
		if err := testcontainers.TerminateContainer(pgContainer); err != nil {
			slog.Error("failed to terminate postgres test container", "error", err)
		}
	}

	dbURL, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		terminate()
		return nil, nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	if err := runTestMigrations(dbURL); err != nil {
		terminate()
		return nil, nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := os.Setenv("DATABASE_URL", dbURL); err != nil {
		terminate()
		return nil, nil, fmt.Errorf("failed to set DATABASE_URL: %w", err)
	}

	pool, err := NewConnectionPool(ctx)
	if err != nil {
		terminate()
		return nil, nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	cleanup := func() {
		pool.Close()
		terminate()
	}

	return pool, cleanup, nil
}

func runTestPostgresContainer(ctx context.Context) (*testContainerPg.PostgresContainer, error) {
	if _, ok := os.LookupEnv("TESTCONTAINERS_RYUK_DISABLED"); !ok {
		if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
			return nil, fmt.Errorf("failed to disable Ryuk: %w", err)
		}
	}

	portStart, portEnd, err := testDBPortRange()
	if err != nil {
		return nil, err
	}

	var lastConflictErr error
	for port := portStart; port <= portEnd; port++ {
		container, err := testContainerPg.Run(ctx,
			"postgres:18-alpine",
			testContainerPg.WithDatabase(testDBName),
			testContainerPg.WithUsername(testDBUser),
			testContainerPg.WithPassword(testDBPassword),
			testcontainers.WithHostConfigModifier(newTestDatabaseHostConfigModifier(strconv.Itoa(port))),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(time.Minute),
			),
		)
		if err == nil {
			return container, nil
		}
		if !isTestDatabasePortConflict(err) {
			return nil, fmt.Errorf("failed to start postgres container: %w", err)
		}
		lastConflictErr = err
	}

	return nil, fmt.Errorf("no available postgres test port in range %d-%d: %w", portStart, portEnd, lastConflictErr)
}

func testDBPortRange() (int, int, error) {
	portStart, err := testDBPortValue("TEST_DB_PORT_START", defaultTestDBPortStart)
	if err != nil {
		return 0, 0, err
	}

	portEnd, err := testDBPortValue("TEST_DB_PORT_END", defaultTestDBPortEnd)
	if err != nil {
		return 0, 0, err
	}

	if portStart > portEnd {
		return 0, 0, fmt.Errorf("TEST_DB_PORT_START must be less than or equal to TEST_DB_PORT_END")
	}

	return portStart, portEnd, nil
}

func testDBPortValue(name string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}

	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid TCP port: %w", name, err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", name)
	}

	return port, nil
}

func isTestDatabasePortConflict(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()
	return strings.Contains(message, "port is already allocated") ||
		strings.Contains(message, "address already in use")
}

func newTestDatabaseHostConfigModifier(hostPort string) func(*container.HostConfig) {
	return func(hostConfig *container.HostConfig) {
		hostConfig.PortBindings = network.PortMap{
			network.MustParsePort("5432/tcp"): {
				{
					HostIP:   netip.MustParseAddr("0.0.0.0"),
					HostPort: hostPort,
				},
			},
		}
	}
}

// runTestMigrations applies the migrations bundled with this package. The
// migrations path is resolved relative to this source file so the helper works
// regardless of the caller's working directory or package.
func runTestMigrations(dbURL string) error {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("could not resolve migrations path")
	}
	migrationsPath := filepath.Join(filepath.Dir(thisFile), "migrations")

	m, err := migrate.New("file://"+migrationsPath, dbURL)
	if err != nil {
		return fmt.Errorf("create migrate instance: %w", err)
	}
	defer func() {
		sourceErr, databaseErr := m.Close()
		if sourceErr != nil {
			slog.Error("failed to close migration source", "error", sourceErr)
		}
		if databaseErr != nil {
			slog.Error("failed to close migration database", "error", databaseErr)
		}
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up failed: %w", err)
	}
	return nil
}
