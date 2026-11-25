---
paths:
  - "**/*_test.go"
  - "internal/mocks/**"
  - "internal/tests/**"
  - "postgres/test.go"
---

# Testing and Mocking

`go test ./...` runs everything (integration tests need Docker); `go test -short ./...` skips the integration tests; `make test-e2e` runs only the E2E suite; `make test-cover` passes `-coverpkg` so the e2e and integration suites count toward the coverage of the packages they exercise; `make show-cover` prints the coverage CI reports.

## Test Naming

- **Files**: One `<name>_test.go` next to each `<name>.go`. Provider-specific tests live in `<provider>_oauth_provider_test.go`, cross-provider tests in `oauth_provider_test.go`, and shared helpers in `helpers_test.go`.
- **Functions**: One `Test<Type>_<Method>` per tested method (`TestNew<Type>` for constructors). Never write a standalone `Test...` function per scenario.
- **Scenarios**: Subtests via `t.Run` with a short description (`"success"`, `"error - <description>"`). Table-driven cases use `t.Run(tc.name, ...)`.

## Controller Tests

- **Test Package**: Use `package_test` (e.g., `controllers_test`) for black-box testing.
- **Mock Setup**: Create mocks for services and middleware using testify/mock.
- **Test Helper**: Use helper functions (e.g., `getControllerArgs()`) to create test HTTP requests and response recorders.
- **Path Values**: Use `req.SetPathValue()` to simulate path parameters.
- **Assertions**:
  - Verify HTTP status codes.
  - Unmarshal and verify response bodies.
  - Assert that mock methods were called with expected parameters.
  - Use `AssertNotCalled` for error paths that should not reach certain layers.
- **Test Coverage**: Include success cases, validation errors, and service error scenarios.

**Example**:

```go
func TestUsersController_CreateUser(t *testing.T) {
    dto := domain.CreateUserDTO{Name: "John Doe", Email: "john.doe@example.com", Password: "password123"}

    t.Run("success", func(t *testing.T) {
        controller, pendingMock, auditMock := newTestSignupUsersController(true)
        pendingMock.On("StartCredentials", dto).Return("pending-uuid", nil).Once()
        auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
            return d.Action == domain.AuditActionSignupRequest && d.Status == domain.AuditStatusSuccess
        })).Return(nil).Once()

        w, req := getControllerArgs("POST", "/users", dto)
        controller.CreateUser(w, req)

        var response api.ResponseBody[any]
        err := json.Unmarshal(w.Body.Bytes(), &response)

        assert.Nil(t, err)
        assert.Equal(t, http.StatusAccepted, w.Code)
        assert.Equal(t, "user.create.pending", response.Message)
        assert.Equal(t, "pending-uuid", findCookie(w.Result().Cookies(), "__Host-pending_signup").Value)
        pendingMock.AssertExpectations(t)
    })
}
```

## Service Tests

- **Mock Repositories**: Use repository mocks to isolate service logic.
- **Password Testing**: Use `bcrypt.CompareHashAndPassword()` to verify password hashing.
- **Mock Verification**: Use `.Run()` callbacks to inspect arguments passed to mocks.
- **Matcher Functions**: Use `mock.MatchedBy()` for complex argument matching.
- **Fixed Clock**: unit tests build services with `testClock` (`testNow`, in `internal/services/clock_test.go`) and assert timestamps with exact equality, never `WithinDuration`/`InDelta`; add boundary subtests (at the instant, one second before). `time.Now` is acceptable only in tests that don't involve time (e.g. integration and E2E tests).
- **Test Coverage**: Test all business logic branches (authorization, validation errors, repository errors, side-effect failures).

**Example**:

```go
func TestPendingSignupService_StartCredentials(t *testing.T) {
    dto := domain.CreateUserDTO{Name: "New User", Email: "  New@Example.com ", Password: "password123"}

    t.Run("success", func(t *testing.T) {
        service, m := newTestPendingSignupService()
        var stored domain.PendingSignup
        var code string
        expectEmailAvailable(m, "new@example.com")
        expectReserveSend(m, "new@example.com", nil)
        expectCreatePending(m, &stored)
        m.emails.On("SendSignupCode", "new@example.com", mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
            code = args.String(1)
        })

        pendingUUID, err := service.StartCredentials(context.Background(), dto)

        require.NoError(t, err)
        assert.Equal(t, pendingUUID, stored.UUID)
        assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte(dto.Password)))
        assert.Equal(t, signupHash(pendingUUID, code), stored.CodeHash)
        m.emails.AssertExpectations(t)
    })
}
```

## Repository Tests

- **Integration Tests**: Repository tests are integration tests that connect to a real database.
- **Scaffolding**: Use `go-resource-scaffolder` to generate the boilerplate for these tests.
- **Test Database**: `postgres.NewTestPool(ctx)` starts an ephemeral `postgres:18-alpine` container with testcontainers (only Docker is needed, no compose file or `migrate` CLI), applies `postgres/migrations` with `golang-migrate` as a library, sets `DATABASE_URL` and returns a pool plus a cleanup function. The host port is the first free one in `15432`–`15499` (override with `TEST_DB_PORT_START`/`TEST_DB_PORT_END`).
- **TestMain Setup**: One `TestMain` per package with integration tests (`internal/repositories/repositories_test.go`, `internal/infra`) calls `NewTestPool`, runs the tests and calls the cleanup.
- **Test Isolation**: Truncate tables between tests using a `truncateTables()` helper function; add new tables to its list.
- **Short Mode**: `TestMain` skips the container with `-short`, and each test calls `t.Skip` when `testing.Short()`.
- **Test Coverage**: Test success cases, constraint violations (e.g., duplicate email), invalid inputs, and not found scenarios.
- **Composition Tests**: Not here. Service flows composed with several real repositories (transaction atomicity) live in `internal/tests/integration` (ADR-006).

**Example**:

```go
func TestMain(m *testing.M) {
    flag.Parse()
    if testing.Short() {
        os.Exit(m.Run())
    }

    pool, cleanup, err := postgres.NewTestPool(context.Background())
    if err != nil {
        log.Fatalf("Could not start testing database: %v", err)
    }
    testDB = pool

    code := m.Run()

    cleanup()

    os.Exit(code)
}

func truncateTables(ctx context.Context, db *pgxpool.Pool) {
    tables := []string{"audit_logs", "email_send_limits", "pending_signups", "session_challenges", "user_sessions", "user_oauth_providers", "users"}
    for _, table := range tables {
        if _, err := db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)); err != nil {
            log.Fatalf("Failed to truncate table %s: %v", table, err)
        }
    }
}
```

## Integration Tests

- **Scope**: `internal/tests/integration` (`package integration_test`, test files only) runs service methods against several real repositories and the ephemeral PostgreSQL, with failure injection to prove transaction atomicity (e.g. a wrapper repository that fails `DeleteAllByUser` and an assertion that nothing was persisted). Mock only what is external (email, OAuth providers). Single-repository SQL tests stay in `internal/repositories`.
- **Layout**: `integration_test.go` has `TestMain` (same pattern as the repositories package) and `truncateTables`; `helpers_test.go` has the failing/blocking repository wrappers and count helpers. Each `<service>_service_test.go` mirrors the service file it covers.
- **Naming**: `Test<Type>_<Method>` (e.g. `TestPasswordService_ResetPassword`), scenarios as subtests; flows with different setups become groups (`t.Run("credentials", ...)`). Each test calls `t.Skip` when `testing.Short()`.

## E2E Tests

- **Scope**: `internal/tests/e2e` (`package e2e_test`, test files only) serves `factories.NewHandler` with `httptest.NewServer` over the real ephemeral PostgreSQL, with no mocks. It covers these flows: sign-up by code (cookie binding, replay) and login, session lifecycle (rotation, per-device logout), concurrent refresh, authorization (user vs admin), step-up, the email change flow (code confirmation in the requesting session only, replay, lock, undo link) and logout-others. Validation, 404/409 errors and rate limiting stay in unit tests. See ADR-006.
- **Email Capture**: `factories.NewDependencies` takes optional `factories.Option`s; `factories.WithEmailProvider` replaces the provider chosen from the config (production passes none). `mailbox_test.go` has `capturingEmailProvider` (concurrency-safe, keeps the last email per recipient) with `otpCode` and `linkToken` helpers that read the 6-digit code (sign-up, step-up and email change) or the link `token` (undo link) from the email text; `TestMain` sets the `EMAIL_*` URLs and passes the mailbox. `client.stepUp(email)` performs a real step-up with it.
- **TestMain Setup**: `e2e_test.go` calls `NewTestPool`, sets the env (`API_ENV=development` so cookies are not `Secure` over http; `JWT_SECRET`; high `RATE_LIMIT_*` because every request shares the `127.0.0.1` bucket; an empty `RESEND_API_KEY` so a key exported from `.env` by the Makefile never sends real email), runs `config.Load`, the audit partitions `RunMaintenance`, `NewDependencies` and `NewHandler`, and exposes `serverURL`. Setup lives in `run(m) int`, which defers the container cleanup and server close and returns 1 on setup errors.
- **Fixtures**: `helpers_test.go` has `truncateTables(t, ctx, pool)` (call it first in each test), `seedUser`/`seedAdmin` (create through the real users repository with a bcrypt hash; extend with new `seedX` helpers, each test seeds only what it uses) and `newClient`, one cookie jar per device, with `do` and `login`.
- **Naming**: `Test<Flow>` (e.g. `TestSessionLifecycle`) is the exception to `Test<Type>_<Method>`, with subtests per step. Each test calls `t.Skip` when `testing.Short()`.

## Mocking Patterns

- **Mock Location**: All mocks are centralized in `internal/mocks/`.
- **Interface Compliance**: Mocks verify interface compliance using `var _ InterfaceName = (*MockName)(nil)`.
- **Testify/Mock**: Use `github.com/stretchr/testify/mock` for mock implementations.
- **Return Handling**: Check if return value is not nil before type assertion to avoid panics.
- **Context Argument**: Most mocks accept `ctx` but leave it out of `m.Called(...)`, so expectations match only the business arguments; follow the existing mock of the interface you extend.
- **Naming Convention**: Mocks are named with the `Mock` suffix (e.g., `UsersServiceMock`, `UsersRepositoryMock`).
- **No Telemetry Mocks**: There are none by design (see `.claude/rules/telemetry.md`).

**Example**:

```go
type UsersServiceMock struct {
    mock.Mock
}

var _ domain.UsersService = (*UsersServiceMock)(nil)

func (m *UsersServiceMock) GetByUUID(ctx context.Context, actor domain.Actor, uuid string) (*domain.User, error) {
    args := m.Called(actor, uuid)
    if args.Get(0) != nil {
        return args.Get(0).(*domain.User), args.Error(1)
    }
    return nil, args.Error(1)
}
```
