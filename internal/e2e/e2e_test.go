package e2e_test

import (
	"context"
	"flag"
	"log"
	"net/http/httptest"
	"os"
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/infra"
	"go-net-http-auth-base/internal/telemetry"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	testDB    *pgxpool.Pool
	serverURL string
	mailbox   = newCapturingEmailProvider()
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if testing.Short() {
		return m.Run()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, cleanup, err := postgres.NewTestPool(ctx)
	if err != nil {
		log.Printf("Could not start testing database: %v", err)
		return 1
	}
	defer cleanup()
	testDB = pool

	for key, value := range map[string]string{
		"API_ENV":                        "development",
		"JWT_SECRET":                     "e2e-test-secret-with-at-least-32-characters",
		"RATE_LIMIT_REQUESTS_PER_SECOND": "1000",
		"RATE_LIMIT_BURST":               "1000",
		"RESEND_API_KEY":                 "",
		"EMAIL_FROM":                     "noreply@example.com",
		"EMAIL_CHANGE_REVERT_URL":        "http://app.test/revert-email-change",
	} {
		if err := os.Setenv(key, value); err != nil {
			log.Printf("Could not set %s: %v", key, err)
			return 1
		}
	}

	cfg, err := config.Load()
	if err != nil {
		log.Printf("Could not load config: %v", err)
		return 1
	}

	if err := infra.NewAuditLogsPartitionManager(pool).RunMaintenance(ctx); err != nil {
		log.Printf("Could not create audit log partitions: %v", err)
		return 1
	}

	deps, err := factories.NewDependencies(pool, cfg, factories.WithEmailProvider(mailbox))
	if err != nil {
		log.Printf("Could not build dependencies: %v", err)
		return 1
	}

	tel, err := telemetry.New(ctx, config.TelemetryConfig{}, "test")
	if err != nil {
		log.Printf("Could not build telemetry: %v", err)
		return 1
	}

	server := httptest.NewServer(factories.NewHandler(ctx, deps, cfg, tel))
	defer server.Close()
	serverURL = server.URL

	return m.Run()
}
