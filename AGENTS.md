# AI Agent Context

This document provides context for AI Agents to understand the project structure, conventions, and commands.

## Project Overview

This a Go-based REST API project. It is a web service that handles user authentication
and other user-related functionalities. The project uses a PostgreSQL database and
follows a layered architecture, separating concerns into controllers, services,
repositories, and domain models.

### Technologies

- **Language:** Go
- **Database:** PostgreSQL
- **HTTP Server:** Standard `net/http`
- **Database Migrations:** `golang-migrate`
- **Database Queries:** `sqlc` for generating type-safe Go code from SQL queries.
- **Live Reloading:** `air` for development.
- **Dependencies:** Managed with Go Modules (`go.mod`).

### Architecture

The project follows a clean architecture pattern:

- `cmd/main.go`: The application's entry point, where the server is initialized
  and routes are registered.
- `config/`: Loads and validates every environment variable (`config.Load`) and
  builds the OAuth client configs.
- `internal/`: Contains the core application logic.
  - `api/`: Defines the JSON request decoding/validation, response structure,
    error mapping and cookies.
  - `controllers/`: Handles HTTP requests and responses, calling services to
    perform business logic.
  - `services/`: Implements the business logic of the application.
  - `repositories/`: Provides an abstraction layer for data access, interacting
    with the database.
  - `providers/`: Adapters for external services (OAuth providers, email).
  - `middlewares/`: HTTP middlewares (auth, role, CORS, rate limit, logger,
    telemetry, request UUID, request context data).
  - `domain/`: Defines the core data structures and interfaces.
  - `factories/`: Composition root. `dependencies.go` builds the shared
    dependency graph (repositories, services, middlewares) once; the other
    files are thin per-controller factories that wire pieces of `Dependencies`
    into a controller. `handler.go` (`NewHandler`) builds the mux, registers
    every controller and applies the global middleware chain; `cmd/main.go` and
    the E2E suite both call it.
  - `mocks/`: testify mocks of the domain interfaces.
  - `e2e/`: End-to-end tests (test files only), see "E2E Tests" below.
  - `infra/`: Background infrastructure tasks (`AuditLogsPartitionManager`).
  - `logger/`, `telemetry/`: `slog` setup and the OpenTelemetry SDK bootstrap.
  - `shared/`: Request context data (`RequestContextData`) shared by
    middlewares, `api` and controllers.
  - `env/`: Typed environment variable lookups used by `config`.
- `postgres/`: Contains database-related code, including the database connection,
  generated queries from `sqlc`, migrations, query tracers and the integration
  test helper (`NewTestPool`).
- `docker/`: Dockerfile, the dev compose (PostgreSQL, pgAdmin, Grafana LGTM),
  the prod compose and the Grafana dashboards.
- `docs/`: ADRs (`adr/`), the generated Swagger spec (`swagger/`), `ERRORS.md`
  and `AUDIT.md`.

## Available Skills

This project provides specialized skills to automate common development tasks. **Agents should prioritize using these skills over manual implementation.**

### 1. Go Resource Scaffolder (`go-resource-scaffolder`)

Scaffolds a complete vertical slice for a new resource, following the project's layered architecture.

- **Generates**: Domain, Repository (w/ Integration Tests), Service (w/ Unit Tests), Controller (w/ Unit Tests), and Factory.
- **Usage**:
  ```bash
  npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName> [--singular]
  ```
- **Example**:
  - `npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts Product` (Creates `products_controller.go`, etc.)
  - `npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts Auth --singular` (Creates `auth_controller.go`)
- **After scaffolding**: Follow the printed next steps (wire the service in `dependencies.go`, register the factory in `cmd/main.go`, add the table and queries, implement the repository placeholders). See `.github/skills/go-resource-scaffolder/SKILL.md`.

### 2. Go Migration Scaffolder (`go-migration-scaffolder`)

Streamlines database schema changes.

- **Generates**: Up/Down migration files and a corresponding `sqlc` query file.
- **Usage**:
  ```bash
  npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts <migration_name>
  ```
- **Example**: `npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts add_products_table`
- **Template phase**: While this is still a template, do not run it; schema changes go into `000001_init_db.up.sql`/`.down.sql` (see `.github/skills/go-migration-scaffolder/SKILL.md`).

## Building and Running

### Development

To run the application in a development environment with live reloading, use
the following command:

```bash
air
```

This command uses `air` to watch for file changes and automatically rebuild and
restart the server.

You can run the following command to ensure that all required tools are installed:

```bash
make setup
```

### Production

To build a production binary, use the following command:

```bash
make build
```

This will create an executable file in the `bin/` directory.

### Database

The project uses Docker Compose to manage the PostgreSQL database. To start the database, run:

```bash
docker compose --env-file .env -f docker/docker-compose.dev.yaml up -d
```

To run database migrations, use the following commands:

- `make migrate-up`: Apply all pending migrations.
- `make migrate-down`: Revert the last migration.
- `make migrate-create name=<migration_name>`: Create a new migration file.

To generate Go code from SQL queries using `sqlc`, run:

```bash
make sqlc-gen
```

### API Docs

To regenerate the Swagger spec (`docs/swagger/`) from the handler annotations, run:

```bash
make swagger-gen
```

## Development Conventions

- **Testing:** The project has a suite of tests for controllers, services, and repositories. Tests live next to the code they test, with the `_test.go` suffix. `go test ./...` runs everything (integration tests need Docker); `go test -short ./...` skips the integration tests; `make test-e2e` runs only the E2E suite; `make show-cover` prints the coverage CI reports.
- **Styling:** The code seems to follow standard Go formatting.
- **JSON Responses:** The `internal/api/response.go` file defines a standardized JSON response format for all API endpoints.
- **Dependency Injection:** `internal/factories/dependencies.go` builds the app's shared dependency graph once (`NewDependencies`), and `cmd/main.go` passes the resulting `*Dependencies` into thin per-controller factories, which promotes loose coupling and testability. `factories.NewHandler(ctx, deps, cfg, tel)` assembles the whole `http.Handler` (routes plus middleware chain) so tests run the production wiring.

## Architecture Decision Records

Architectural decisions are recorded in `docs/adr/` (index and rules in `docs/adr/README.md`). When a decision made while building a feature meets any of the criteria below, write an ADR in the same PR as the feature:

- It changes or adds a convention described in this file (layers, errors, transactions, telemetry, testing).
- It adds or replaces an infrastructure dependency (database, queue, external provider, core library).
- It changes the security model (tokens, sessions, authorization) or accepts a residual risk.
- It is hard to reverse, or real alternatives were weighed.

Local choices (naming, a new helper, a refactor that keeps behavior) do not need an ADR. When in doubt, ask the user.

- **Format:** Nygard (Status, Date, Context, Decision, Consequences), in English, as `docs/adr/ADR-00N-short-title.md` with the next number. Add it to the index table.
- **Immutability:** Never rewrite the decision of an accepted ADR. Write a new ADR and set the old one's status to `Superseded by ADR-00N`.
- **Diagrams (optional):** Add one only when the decision has a structure or flow that text does not explain well. Install the pinned Archify with `make install-archify` (Node 18+), follow `.tools/archify/SKILL.md`, and commit only the JSON source and the SVG export to `docs/adr/diagrams/` (see `docs/adr/README.md`). If Archify is unavailable, ship the ADR without the diagram.
- **Keep this file in sync:** If the ADR changes a convention, update the matching section of this file in the same PR.

## Code Patterns and Conventions

### Layered Architecture Pattern

The project follows a strict three-layer architecture with clear separation of concerns:

#### 1. Controllers Layer (`internal/controllers/`)

Controllers handle HTTP requests and responses. Key patterns:

- **Constructor Pattern**: Each controller is initialized with a constructor function (e.g., `NewUsersController`) that accepts dependencies via dependency injection.
- **Interface Implementation**: Controllers implement the `Controller` interface which requires a `RegisterRoutes(*http.ServeMux)` method.
- **Route Registration**: Routes are registered using Go 1.22+ HTTP method-specific patterns (e.g., `POST /users`, `GET /users/{uuid}`).
- **Middleware Integration**: Controllers receive middleware instances and apply them using the `Use()` method on protected routes.
- **Request Handling**:
  - Use `api.DecodeAndValidate[T](r)` to decode (strict JSON parsing, single-object body) and validate DTOs against their `validate` struct tags in one step.
  - Extract path parameters using `r.PathValue("param")`.
  - Extract context values (e.g., authenticated user UUID) using `r.Context().Value(key)`.
- **Validation**: `internal/api/request.go` wires a single `go-playground/validator` instance used by `DecodeAndValidate`. Decode or validation failures return a `domain.ValidationError` with per-field `details`, mapped to `400` by `internal/api/errors.go`. DTOs declare rules via `validate:"..."` tags (e.g., `validate:"required,email"`) in `internal/domain/*.go`.
- **Response Handling**:
  - Use `api.WriteJSONResponse()` helper for consistent JSON responses.
  - Include appropriate HTTP status codes (201 for creation, 204 for deletion, etc.).
  - Use message keys (e.g., `"user.create.success"`) for i18n support.
  - Return error details in the `Error` field of the response body.
- **Error Handling**: Map service errors to appropriate HTTP status codes (400 for bad request, 404 for not found, 500 for internal errors).
- **API Docs (Swagger)**: Every handler carries swaggo/swag annotations (Swagger 2.0, general info in `cmd/main.go`). Run `make swagger-gen` after changing them: it regenerates `docs/swagger/` (committed), and CI fails on drift. `DocsController` serves Swagger UI in every environment: `/swagger/` (exact) is a public login gate (embedded static page that checks `GET /users/me`, refreshes once, or signs in via `POST /auth/login`, then goes to `/swagger/index.html`), and everything else under `/swagger/` (UI, `doc.json`) is behind the auth and admin role middlewares. Auth is cookie-only, which Swagger 2.0 cannot express, so there are no `securityDefinitions`; "Try it out" works because the browser sends the `access_token` cookie. The UI top bar has a Logout button, and a successful "Try it out" `POST /auth/logout` also returns to the gate (injected via `httpSwagger.AfterScript`/`UIConfig` from `assets/swagger_ui_*.js`).

**Example Structure**:

```go
type UsersController struct {
    userService    domain.UsersService
    auditService   domain.AuditService
    authMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*UsersController)(nil)

func NewUsersController(
    service domain.UsersService,
    auditService domain.AuditService,
    authMiddleware middlewares.HandlerMiddleware,
) *UsersController {
    return &UsersController{
        userService:    service,
        auditService:   auditService,
        authMiddleware: authMiddleware,
    }
}

func (c *UsersController) RegisterRoutes(router *http.ServeMux) {
    router.HandleFunc("POST /users", c.CreateUser)
    router.HandleFunc("GET /users/me", c.authMiddleware.Use(c.GetMe))
}

// factories/users_factory.go
func UsersFactory(deps *Dependencies) controllers.Controller {
    return controllers.NewUsersController(deps.UsersService, deps.AuditService, deps.AuthMiddleware)
}
```

#### 2. Services Layer (`internal/services/`)

Services implement business logic. Key patterns:

- **Constructor Pattern**: Services are created using factory functions (e.g., `NewUserService`) that accept repository dependencies.
- **Interface Implementation**: Services implement domain interfaces (e.g., `domain.UsersService`).
- **Private Struct, Public Interface**: Service structs are lowercase (private), but implement uppercase (public) interfaces defined in the domain package.
- **Business Logic**:
  - Services orchestrate repository calls and apply business rules.
  - Password hashing is performed in the service layer using `bcrypt.GenerateFromPassword()`.
  - Input shape is validated in the controller (`api.DecodeAndValidate`); services enforce business rules (e.g., self-or-admin access through `Actor.CanAccess`, which returns a `ForbiddenError`).
  - Services perform partial updates by fetching existing entities, modifying only provided fields, then calling repository update.
- **Email**: `domain.EmailProvider` (`Send`) is built once in `factories.Dependencies`: `ResendEmailProvider` when `RESEND_API_KEY` is set, otherwise `LogEmailProvider` (development). `RESEND_API_KEY`, `EMAIL_FROM` and `EMAIL_VERIFICATION_URL` are required outside development; all are loaded and validated in `config/config.go`.
- **Email Verification**: `domain.EmailVerificationService` (`services.NewEmailVerificationService`, depends only on `TokenService`, `EmailProvider` and the verification URL) sends the mail (`SendVerificationEmail`) and checks its token (`VerifyVerificationToken`). `UsersService` owns the flow: `Create` (`POST /users`) sends the mail and only logs a failure (`CreateOAuth` never sends), `VerifyEmail` backs `POST /users/verify-email` and `ResendVerification` backs `POST /users/resend-verification` (silent for unknown or already verified emails). The link carries a JWT with audience `email_verification_token` (24h). OAuth account creation requires a provider-verified email, and linking into an existing account requires both provider and local `email_verified`.
- **Email Normalization**: Services always pass emails through the unexported `normalizeEmail` helper (`services/helpers.go`, trim + lowercase) before lookup or write; repositories receive already normalized emails; the database enforces a unique index on `lower(email)`.
- **Refresh Sessions**: Multi-device: each login (credentials or OAuth, via `startSession`) creates a row in `user_sessions` (`current_jti`, `last_used_at`, `expires_at` = login + `SESSION_MAX_AGE`, never extended on rotation), inside one `WithinTx` that first deletes the user's expired or idle sessions and then trims the user to the newest `MAX_SESSIONS_PER_USER` (optional, default 10; least recently used evicted). Refresh tokens carry `sub`, `sid` and `jti`; access tokens carry `sub` and `sid` (`tokenService` rejects either without `sid`). Refresh loads the session by `sid` + `sub`, rejects it past `expires_at`, and rotates the `jti` through `SessionsRepository.RotateJTI` (per-session atomic compare-and-set, keeping the same `sid`); a reused or stale token, or a lost concurrent refresh, deletes only that session (the user's other devices stay signed in). There is no grace window, so clients must send one refresh at a time. `POST /auth/logout` is authenticated (`AuthMiddleware` puts `SessionUUID` in `shared.RequestContextData`) and deletes only the current session; the stateless access token stays valid for up to 15 minutes after logout, but the session can no longer be refreshed. With an expired access token, clients refresh first and then log out.
- **Token Interfaces**: All JWTs are signed and verified by the dependency-free `tokenService` (`services.NewTokenService`, holds only the JWT secret; `domain.TokenService`), used by `AuthService` (which delegates its token methods to it) and `EmailVerificationService`. `domain.TokenVerifier` (`VerifyToken`) is what middlewares depend on; `domain.TokenGenerator` (`GenerateToken`) is separate and not part of `AuthService`. Depend on the narrowest one.
- **Error Handling**: Services return domain-specific errors with meaningful messages (e.g., `"users.forbidden"`). See `docs/ERRORS.md`.
- **Multi-Step Orchestration**: Flows spanning several steps and services (e.g., `AuthService.OAuthLogin`, which verifies the state token, resolves/creates the user via `UsersService`, links the OAuth provider, and mints tokens) are implemented as a single service method. Controllers stay thin: decode input, call the one service method, then handle the HTTP concerns (cookies, redirect, audit log).

**Example Structure**:

```go
type usersService struct {
    repo              domain.UsersRepository
    emailVerification domain.EmailVerificationService
}

func NewUserService(repo domain.UsersRepository, emailVerification domain.EmailVerificationService) domain.UsersService {
    return &usersService{repo: repo, emailVerification: emailVerification}
}

func (s *usersService) Create(ctx context.Context, dto domain.CreateUserDTO) (*domain.User, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
    if err != nil {
        return nil, domain.NewInternalServerError("users.create.passwordHashingFailed", err)
    }
    user := domain.User{
        Name:         dto.Name,
        Email:        normalizeEmail(dto.Email),
        PasswordHash: string(hash),
        Role:         domain.RoleUser,
    }
    created, err := s.repo.Create(ctx, user)
    if err != nil {
        return nil, err
    }

    if err := s.emailVerification.SendVerificationEmail(ctx, created); err != nil {
        slog.ErrorContext(ctx, "verification email failed", "error", err, "user_uuid", created.UUID)
    }

    return created, nil
}
```

#### 3. Repositories Layer (`internal/repositories/`)

Repositories handle data persistence. Key patterns:

- **Constructor Pattern**: Repositories use factory functions (e.g., `NewUsersPostgresRepository`) that accept a `postgres.DBTX` interface.
- **Interface Implementation**: Repositories implement domain repository interfaces.
- **SQLC Integration**: Repositories use `postgres.Queries` generated by `sqlc` for type-safe database operations.
- **Context Usage**: All repository methods take `context.Context` as the first argument and propagate it to `postgres.Queries` calls; controllers pass `r.Context()` through services down to repositories.
- **UUID Handling**: UUIDs are converted between string and `pgtype.UUID` with the `parseUUID` helper (`repositories/helpers.go`), which returns a domain error for invalid input.
- **Error Mapping**: Infrastructure errors are mapped to domain errors with `isNoRowsError`, `isConflictError` and `isForeignKeyViolationError`; anything else becomes an `InternalServerError` wrapping the cause (see `docs/ERRORS.md`).
- **Data Transformation**: Use dedicated mapper functions (e.g., `toDomainUser()`) to convert between database models and domain models.
- **Returned Entities**: Repository `Create()`/`Update()` methods receive the entity by value and return a pointer to the persisted entity, including database-generated fields (UUID, timestamps).
- **pgtype Usage**: Nullable database fields use `pgtype` types (e.g., `pgtype.Text`, `pgtype.UUID`).
- **Transactions**: Services that need several repository calls to succeed or fail together depend on `domain.Transactor` and call `WithinTx(ctx, func(ctx) error)`, using the closure's `ctx` for every call inside it. Always name the closure parameter `ctx` so it shadows the outer one: using the outer context runs the query outside the transaction without any error. Cover each transactional flow with an integration test that forces a failure and asserts nothing was persisted (e.g. `oauth_login_transaction_test.go`). `repositories.PostgresTransactor` stores the `pgx.Tx` in the context, and repositories are built on `repositories.TxAwareDB` (a `postgres.DBTX`) so they join the active transaction automatically. A nested `WithinTx` joins the outer transaction.

**Example Structure**:

```go
type UsersPostgresRepository struct {
    q *postgres.Queries
}

func NewUsersPostgresRepository(db postgres.DBTX) domain.UsersRepository {
    return &UsersPostgresRepository{
        q: postgres.New(db),
    }
}

func (r *UsersPostgresRepository) Create(ctx context.Context, user domain.User) (*domain.User, error) {
    params := postgres.CreateUserParams{
        Name:          user.Name,
        Email:         user.Email,
        PasswordHash:  pgtype.Text{String: user.PasswordHash, Valid: true},
        EmailVerified: user.EmailVerified,
    }

    createdUser, err := r.q.CreateUser(ctx, params)
    if err != nil {
        if conflictErr := isConflictError(err, "users.email.conflict"); conflictErr != nil {
            return nil, conflictErr
        }
        return nil, domain.NewInternalServerError("users.internalServerError", err)
    }

    user = toDomainUser(createdUser)
    return &user, nil
}

func toDomainUser(user postgres.User) domain.User {
    var uuidBytes = user.Uuid.Bytes
    return domain.User{
        UUID:          uuid.UUID(uuidBytes).String(),
        Name:          user.Name,
        Email:         user.Email,
        Role:          domain.UserRole(user.Role),
        EmailVerified: user.EmailVerified,
        PasswordHash:  user.PasswordHash.String,
        CreatedAt:     user.CreatedAt.Time.Unix(),
        UpdatedAt:     user.UpdatedAt.Time.Unix(),
    }
}
```

### Testing Patterns

#### Test Naming

- **Files**: One `<name>_test.go` next to each `<name>.go`. Provider-specific tests live in `<provider>_oauth_provider_test.go`, cross-provider tests in `oauth_provider_test.go`, and shared helpers in `helpers_test.go`.
- **Functions**: One `Test<Type>_<Method>` per tested method (`TestNew<Type>` for constructors). Never write a standalone `Test...` function per scenario.
- **Scenarios**: Subtests via `t.Run` with a short description (`"success"`, `"error - <description>"`). Table-driven cases use `t.Run(tc.name, ...)`.

#### Controller Tests

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
    user := &domain.User{UUID: "test-uuid", Name: dto.Name, Email: dto.Email, Role: domain.RoleUser}

    t.Run("success", func(t *testing.T) {
        controller, serviceMock, auditMock, _ := newTestUsersController()
        serviceMock.On("Create", dto).Return(user, nil)
        auditMock.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
            return d.Action == domain.AuditActionUserCreate && d.Status == domain.AuditStatusSuccess
        })).Return(nil)

        w, req := getControllerArgs("POST", "/users/", dto)
        controller.CreateUser(w, req)

        var response api.ResponseBody[domain.User]
        err := json.Unmarshal(w.Body.Bytes(), &response)

        assert.Nil(t, err)
        assert.Equal(t, http.StatusCreated, w.Code)
        assert.Equal(t, *user, response.Data)
        serviceMock.AssertCalled(t, "Create", dto)
    })
}
```

#### Service Tests

- **Mock Repositories**: Use repository mocks to isolate service logic.
- **Password Testing**: Use `bcrypt.CompareHashAndPassword()` to verify password hashing.
- **Mock Verification**: Use `.Run()` callbacks to inspect arguments passed to mocks.
- **Matcher Functions**: Use `mock.MatchedBy()` for complex argument matching.
- **Test Coverage**: Test all business logic branches (authorization, validation errors, repository errors, side-effect failures).

**Example**:

```go
func TestUsersService_Create(t *testing.T) {
    dto := domain.CreateUserDTO{Name: "Test User", Email: "Test@Example.com", Password: "password123"}
    created := &domain.User{UUID: "generated-uuid", Name: "Test User", Email: "test@example.com", Role: domain.RoleUser}

    t.Run("success", func(t *testing.T) {
        repo := new(mocks.UsersRepositoryMock)
        sender := new(mocks.EmailVerificationServiceMock)
        service := services.NewUserService(repo, sender)

        repo.On("Create", mock.AnythingOfType("domain.User")).Return(created, nil).Once().Run(func(args mock.Arguments) {
            userArg := args.Get(0).(domain.User)
            assert.Equal(t, "test@example.com", userArg.Email)
            assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(userArg.PasswordHash), []byte(dto.Password)))
        })
        sender.On("SendVerificationEmail", mock.Anything, created).Return(nil).Once()

        user, err := service.Create(context.Background(), dto)

        assert.NoError(t, err)
        assert.Equal(t, created, user)
        repo.AssertExpectations(t)
        sender.AssertExpectations(t)
    })
}
```

#### Repository Tests

- **Integration Tests**: Repository tests are integration tests that connect to a real database.
- **Scaffolding**: Use `go-resource-scaffolder` to generate the boilerplate for these tests.
- **Test Database**: `postgres.NewTestPool(ctx)` starts an ephemeral `postgres:18-alpine` container with testcontainers (only Docker is needed, no compose file or `migrate` CLI), applies `postgres/migrations` with `golang-migrate` as a library, sets `DATABASE_URL` and returns a pool plus a cleanup function. The host port is the first free one in `15432`–`15499` (override with `TEST_DB_PORT_START`/`TEST_DB_PORT_END`).
- **TestMain Setup**: One `TestMain` per package with integration tests (`internal/repositories/repositories_test.go`, `internal/infra`) calls `NewTestPool`, runs the tests and calls the cleanup.
- **Test Isolation**: Truncate tables between tests using a `truncateTables()` helper function; add new tables to its list.
- **Short Mode**: `TestMain` skips the container with `-short`, and each test calls `t.Skip` when `testing.Short()`.
- **Test Coverage**: Test success cases, constraint violations (e.g., duplicate email), invalid inputs, and not found scenarios.
- **Composition Tests**: Service + repository flows whose failure cannot be forced cleanly over HTTP (transaction atomicity) live here too, e.g. `oauth_login_transaction_test.go` and `credentials_login_transaction_test.go`.

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
    tables := []string{"audit_logs", "user_sessions", "user_oauth_providers", "users"}
    for _, table := range tables {
        if _, err := db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)); err != nil {
            log.Fatalf("Failed to truncate table %s: %v", table, err)
        }
    }
}
```

#### E2E Tests

- **Scope**: `internal/e2e` (`package e2e_test`, test files only) serves `factories.NewHandler` with `httptest.NewServer` over the real ephemeral PostgreSQL, with no mocks. It covers four flows: sign-up and login, session lifecycle (rotation, per-device logout), concurrent refresh and authorization (user vs admin). Validation, 404/409 errors and rate limiting stay in unit tests. Email verification is a known gap (no seam to capture the link). See ADR-006.
- **TestMain Setup**: `e2e_test.go` calls `NewTestPool`, sets the env (`API_ENV=development` so cookies are not `Secure` over http; `JWT_SECRET`; high `RATE_LIMIT_*` because every request shares the `127.0.0.1` bucket; an empty `RESEND_API_KEY` so a key exported from `.env` by the Makefile never sends real email), runs `config.Load`, the audit partitions `RunMaintenance`, `NewDependencies` and `NewHandler`, and exposes `serverURL`. Setup lives in `run(m) int`, which defers the container cleanup and server close and returns 1 on setup errors.
- **Fixtures**: `helpers_test.go` has `truncateTables(t, ctx, pool)` (call it first in each test), `seedUser`/`seedAdmin` (create through the real users repository with a bcrypt hash; extend with new `seedX` helpers, each test seeds only what it uses) and `newClient`, one cookie jar per device, with `do` and `login`.
- **Naming**: `Test<Flow>` (e.g. `TestSessionLifecycle`) is the exception to `Test<Type>_<Method>`, with subtests per step. Each test calls `t.Skip` when `testing.Short()`.

### Mocking Patterns

- **Mock Location**: All mocks are centralized in `internal/mocks/`.
- **Interface Compliance**: Mocks verify interface compliance using `var _ InterfaceName = (*MockName)(nil)`.
- **Testify/Mock**: Use `github.com/stretchr/testify/mock` for mock implementations.
- **Return Handling**: Check if return value is not nil before type assertion to avoid panics.
- **Context Argument**: Most mocks accept `ctx` but leave it out of `m.Called(...)`, so expectations match only the business arguments; follow the existing mock of the interface you extend.
- **Naming Convention**: Mocks are named with the `Mock` suffix (e.g., `UsersServiceMock`, `UsersRepositoryMock`).

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

### Domain Layer

- **Interfaces**: All service and repository interfaces are defined in the `domain` package.
- **DTOs**: Data Transfer Objects are defined for create and update operations (e.g., `CreateUserDTO`, `UserUpdateDTO`).
- **Pointer Fields**: Update DTOs use pointer fields to distinguish between "not provided" and "set to zero value".
- **Domain Models**: Core entities (e.g., `User`) are defined in the domain package with all necessary fields.
- **Enums**: Use typed constants for enums (e.g., `UserRole` with `RoleAdmin`/`RoleUser`, `TokenAudience`, `OAuthProviderName`).
- **Validation Tags**: Request DTOs declare their input rules with `validate:"..."` tags (e.g., `CreateUserDTO.Password` is `validate:"required,min=8"`).

### General Best Practices

- **Error Messages**: Use dot-separated keys for error messages (e.g., `"users.email.conflict"`) to support internationalization.
- **Pointer Usage**: Services and repositories receive DTOs and entities by value and return pointers to entities (`*domain.User`), so a `nil` result pairs with an error.
- **Dependency Injection**: All dependencies are injected via constructors, never created inside the dependent struct. Shared instances are built once in the composition root (`internal/factories/dependencies.go`), not re-created per factory.
- **Interface-Driven Design**: Program to interfaces, not implementations. This allows easy mocking and testing.
- **Comments**: The code is self-documenting. Comments are allowed only for swag annotations on controller handlers (and the general API info above `main` in `cmd/main.go`) and for explaining complex business logic. No decorative godoc.
- **Exact Errors**: Don't wrap errors unnecessarily; return them as-is unless adding valuable context.

### Telemetry

- **SDK used directly**: `internal/telemetry` (`telemetry.New`, `Shutdown`) bootstraps the OpenTelemetry SDK once in `cmd/main.go` (OTLP/HTTP traces, metrics and logs) and flushes it after the server shuts down.
- **Dependency Rule**: `go.opentelemetry.io/otel*` may only be imported in `internal/telemetry`, `internal/middlewares`, `internal/logger`, `internal/factories`, `postgres` and `cmd`; never in `services`, `controllers`, `domain` or `repositories`.
- **No Domain Abstraction**: There is deliberately no `TelemetryProvider`/`Tracer`/`Meter` interface, no NoOp provider and no telemetry mocks.
- **Gating**: Everything is gated by `OTEL_ENABLED` (default `false`, which wires nothing and returns no-op providers). `OTEL_ENABLED`, `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_TRACES_SAMPLER_ARG` are loaded and validated in `config/config.go`.
- **HTTP Middleware**: `TelemetryMiddleware` (`otelhttp` plus a route hook, built by `factories.TelemetryFactory`, a pass-through when disabled) runs as `requestContextData -> requestUUID -> telemetry -> logger -> cors -> rateLimit -> mux`. It must sit inside `requestContextData` (which copies the request, hiding the `r.Pattern` the mux sets), outside `logger` (so the request log has the span in its context) and outside `cors`/`rateLimit` (so 403/429 are measured). The error a handler stored in `RequestContextData.Error` (set by `api.HandleError`) is recorded on the span as an `exception` event, so the trace shows why a request failed; the span status still follows the HTTP status.
- **Health Checks**: `GET /health` and `GET /ready` produce neither spans nor metrics.
- **Low Cardinality**: Metrics only carry the route pattern as `http.route` (never the raw path) and a constant `server.address` and `server.port` (the service name and the API port, never the client `Host` header). The request UUID goes on spans only (`app.request.uuid`), never on metrics.
- **DB Telemetry**: `postgres.OTelQueryTracer` (built in `cmd/main.go` with the database name parsed from `DATABASE_URL` via `pgx.ParseConfig`, only when enabled and passed to `NewConnectionPool`, which composes it with the `SlowQueryTracer` through pgx `multitracer`) creates a CLIENT span per query named after the sqlc query name (fallback: first SQL keyword) and records `db.client.operation.duration`. `db.query.text` is recorded on spans, but query args never are (PII), and `pgx.ErrNoRows` is not an error. `error.type` is the SQLSTATE for Postgres errors (also set as `db.response.status_code` on spans), `canceled` for `context.Canceled`, else the Go error type. Metric attributes are only `db.system.name`, `db.query.summary`, `db.operation.name` and `error.type`. The `BEGIN`/`COMMIT`/`ROLLBACK` spans produced by `WithinTx` land in the same histogram.
- **Pool and Runtime Metrics**: `postgres.RegisterPoolMetrics` (called in `cmd/main.go` only when enabled, unregistered before `pool.Close`) observes `db.client.connection.count` (`db.client.connection.state` = `idle`/`used`), `db.client.connection.max` and `db.client.connection.empty_acquire` (acquires that waited: pool exhaustion) from one `pool.Stat()` per collection. `telemetry.New` also starts the `contrib/instrumentation/runtime` Go metrics (`go.goroutine.count`, `go.memory.*`, `go.processor.limit`, ...).
- **Dashboards**: Grafana dashboards (`api-red`, `go-runtime`, `database`, `logs`, `request-investigation`, each with a stat row on top and a dashboards dropdown) live in `docker/grafana/dashboards/` and are provisioned into the `lgtm` service of `docker/docker-compose.dev.yaml` through `docker/grafana/provisioning/dashboards.yaml`. Metric names in queries are the Prometheus-translated OTel names (dots to underscores, unit suffix, `_total` for counters); update them if an instrument is renamed. In the `logs` dashboard `detected_level`, `path`, `status` and `trace_id` are Loki structured metadata, so they are filtered after the stream selector (`{service_name=...} | detected_level=~...`), never inside the braces. `request-investigation` is the per-request view: paste a request UUID to list its traces (TraceQL on `span.app.request.uuid`), pick one, and the Trace ID box drives the waterfall, the database spans and the logs (`trace_id`). Grafana cannot turn a UUID into a trace ID inside a variable, so the trace table links set `var-trace_id`. The image's bundled sample dashboards are disabled by mounting `docker/grafana/provisioning/empty.yaml` over its `grafana-dashboards.yaml`.
- **Logs**: When enabled, `cmd/main.go` calls `logger.Setup` again with an `otelslog` handler, so logs fan out to stdout and OTLP (Loki); the stdout handler adds `trace_id`/`span_id` when the context has a span. Both handlers record the call site (`AddSource` and `otelslog.WithSource`): `source` on stdout, `code.*` attributes in Loki. Always use `slog.*Context(ctx, ...)` in request paths so logs carry `trace_id`/`span_id`. `LogEmailProvider` no longer logs email bodies (the verification link carries a JWT).
