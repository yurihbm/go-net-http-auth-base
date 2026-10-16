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
- `internal/`: Contains the core application logic.
  - `api/`: Defines the JSON response structure.
  - `controllers/`: Handles HTTP requests and responses, calling services to
    perform business logic.
  - `services/`: Implements the business logic of the application.
  - `repositories/`: Provides an abstraction layer for data access, interacting
    with the database.
  - `domain/`: Defines the core data structures and interfaces.
  - `factories/`: Composition root. `dependencies.go` builds the shared
    dependency graph (repositories, services, middlewares) once; the other
    files are thin per-controller factories that wire pieces of `Dependencies`
    into a controller.
- `postgres/`: Contains database-related code, including the database connection,
  generated queries from `sqlc`, and migrations.
- `docker/`: Contains Docker-related files for setting up the development environment.

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

### 2. Go Migration Scaffolder (`go-migration-scaffolder`)

Streamlines database schema changes.

- **Generates**: Up/Down migration files and a corresponding `sqlc` query file.
- **Usage**:
  ```bash
  npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts <migration_name>
  ```
- **Example**: `npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts add_products_table`

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
docker-compose -f docker/docker-compose.yaml up -d
```

To run database migrations, use the following commands:

- `make migrate-up`: Apply all pending migrations.
- `make migrate-down`: Revert the last migration.
- `make migrate-create name=<migration_name>`: Create a new migration file.

To generate Go code from SQL queries using `sqlc`, run:

```bash
make sqlc-gen
```

## Development Conventions

- **Testing:** The project has a suite of tests for controllers, services, and repositories. Tests are located in the same package as the code they are testing, with the `_test.go` suffix.
- **Styling:** The code seems to follow standard Go formatting.
- **JSON Responses:** The `internal/api/response.go` file defines a standardized JSON response format for all API endpoints.
- **Dependency Injection:** `internal/factories/dependencies.go` builds the app's shared dependency graph once (`NewDependencies`), and `cmd/main.go` passes the resulting `*Dependencies` into thin per-controller factories, which promotes loose coupling and testability.

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

**Example Structure**:

```go
type UsersController struct {
    userService    domain.UsersService
    authMiddleware middlewares.Middleware
}

func NewUsersController(service domain.UsersService, authMiddleware middlewares.Middleware) *UsersController {
    return &UsersController{
        userService:    service,
        authMiddleware: authMiddleware,
    }
}

func (c *UsersController) RegisterRoutes(router *http.ServeMux) {
    router.HandleFunc("POST /users", c.CreateUser)
    router.HandleFunc("GET /users/me", c.authMiddleware.Use(c.GetMe))
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
  - Validation logic (e.g., checking if password is required for email auth) is handled here.
  - Services perform partial updates by fetching existing entities, modifying only provided fields, then calling repository update.
- **Email**: `domain.EmailProvider` (`Send`) is built once in `factories.Dependencies`: `ResendEmailProvider` when `RESEND_API_KEY` is set, otherwise `LogEmailProvider` (development). `RESEND_API_KEY`, `EMAIL_FROM` and `EMAIL_VERIFICATION_URL` are required outside development and `SESSION_MAX_AGE` (default 30d) is optional; all are loaded and validated in `config/config.go`.
- **Email Verification**: `domain.EmailVerificationService` (`services.NewEmailVerificationService`, depends only on `TokenService`, `EmailProvider` and the verification URL) sends the mail (`SendVerificationEmail`) and checks its token (`VerifyVerificationToken`). `UsersService` owns the flow: `Create` (`POST /users`) sends the mail and only logs a failure (`CreateOAuth` never sends), `VerifyEmail` backs `POST /users/verify-email` and `ResendVerification` backs `POST /users/resend-verification` (silent for unknown or already verified emails). The link carries a JWT with audience `email_verification_token` (24h). OAuth account creation requires a provider-verified email, and linking into an existing account requires both provider and local `email_verified`.
- **Email Normalization**: Always pass emails through `domain.NormalizeEmail` (trim + lowercase) before lookup or write; the database enforces a unique index on `lower(email)`.
- **Refresh Sessions**: One active session per user, tracked in `users.current_refresh_jti`. Refresh tokens carry `jti` and `auth_time`; rotation goes through `UsersRepository.RotateRefreshJTI` (atomic compare-and-set), so a reused token is rejected. Refresh is also rejected once `auth_time` is older than `SESSION_MAX_AGE`. `Logout` clears the stored `jti` and accepts an expired but validly signed access token (only there).
- **Token Interfaces**: All JWTs are signed and verified by the dependency-free `tokenService` (`services.NewTokenService`, holds only the JWT secret; `domain.TokenService`), used by `AuthService` (which delegates its token methods to it) and `EmailVerificationService`. `domain.TokenVerifier` (`VerifyToken`) is what middlewares depend on; `domain.TokenGenerator` (`GenerateToken`) is separate and not part of `AuthService`. Depend on the narrowest one.
- **Error Handling**: Services return domain-specific errors with meaningful messages (e.g., `"user.create.password_required"`).
- **Multi-Step Orchestration**: Flows spanning several steps and services (e.g., `AuthService.OAuthLogin`, which verifies the state token, resolves/creates the user via `UsersService`, links the OAuth provider, and mints tokens) are implemented as a single service method. Controllers stay thin: decode input, call the one service method, then handle the HTTP concerns (cookies, redirect, audit log).

**Example Structure**:

```go
type usersService struct {
    repo domain.UsersRepository
}

func NewUserService(repo domain.UsersRepository) domain.UsersService {
    return &usersService{repo: repo}
}

func (s *usersService) Create(dto *domain.CreateUserDTO) (*domain.User, error) {
    // Business logic + validation
    user := &domain.User{
        Name:  dto.Name,
        Email: dto.Email,
    }

    if dto.AuthMethod == domain.AuthMethodEmail {
        if dto.Password == nil {
            return nil, errors.New("user.create.password_required")
        }
        hash, err := bcrypt.GenerateFromPassword([]byte(*dto.Password), bcrypt.DefaultCost)
        if err != nil {
            return nil, err
        }
        user.PasswordHash = string(hash)
    }

    err := s.repo.Create(user)
    return user, err
}
```

#### 3. Repositories Layer (`internal/repositories/`)

Repositories handle data persistence. Key patterns:

- **Constructor Pattern**: Repositories use factory functions (e.g., `NewUsersPostgresRepository`) that accept a `postgres.DBTX` interface.
- **Interface Implementation**: Repositories implement domain repository interfaces.
- **SQLC Integration**: Repositories use `postgres.Queries` generated by `sqlc` for type-safe database operations.
- **Context Usage**: All repository methods take `context.Context` as the first argument and propagate it to `postgres.Queries` calls; controllers pass `r.Context()` through services down to repositories.
- **UUID Handling**: UUIDs are converted between string and `pgtype.UUID` format for database operations using `uuid.Parse()`.
- **Data Transformation**: Use dedicated mapper functions (e.g., `toDomainUser()`) to convert between database models and domain models.
- **Pointer Updates**: Repository `Create()` methods update the passed entity pointer with database-generated fields (UUID, timestamps).
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
        Name:  user.Name,
        Email: user.Email,
    }

    createdUser, err := r.q.CreateUser(ctx, params)
    if err != nil {
        return nil, err
    }

    user = toDomainUser(createdUser)
    return &user, nil
}

func toDomainUser(user postgres.User) domain.User {
    var uuidBytes = user.Uuid.Bytes
    return domain.User{
        UUID:      uuid.UUID(uuidBytes).String(),
        Name:      user.Name,
        Email:     user.Email,
        CreatedAt: user.CreatedAt.Time.Unix(),
        UpdatedAt: user.UpdatedAt.Time.Unix(),
    }
}
```

### Testing Patterns

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
func TestCreateUser(t *testing.T) {
    t.Run("success", func(t *testing.T) {
        controller, serviceMock, _ := newTestUsersController()
        serviceMock.On("Create", &dto).Return(user, nil)

        w, req := getControllerArgs("POST", "/users/", dto)
        controller.CreateUser(w, req)

        var response api.ResponseBody[domain.User]
        err := json.Unmarshal(w.Body.Bytes(), &response)

        assert.Nil(t, err)
        assert.Equal(t, http.StatusCreated, w.Code)
        assert.Equal(t, response.Data, *user)
        serviceMock.AssertCalled(t, "Create", &dto)
    })
}
```

#### Service Tests

- **Mock Repositories**: Use repository mocks to isolate service logic.
- **Password Testing**: Use `bcrypt.CompareHashAndPassword()` to verify password hashing.
- **Mock Verification**: Use `.Run()` callbacks to inspect arguments passed to mocks.
- **Matcher Functions**: Use `mock.MatchedBy()` for complex argument matching.
- **Test Coverage**: Test all business logic branches (different auth methods, validation errors, repository errors).

**Example**:

```go
func TestUsersService_Create(t *testing.T) {
    repo := new(mocks.UsersRepositoryMock)
    service := services.NewUserService(repo)

    t.Run("success with email auth", func(t *testing.T) {
        password := "password123"
        dto := &domain.CreateUserDTO{
            AuthMethod: domain.AuthMethodEmail,
            Password:   &password,
        }

        repo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil).Once().Run(func(args mock.Arguments) {
            userArg := args.Get(0).(*domain.User)
            err := bcrypt.CompareHashAndPassword([]byte(userArg.PasswordHash), []byte(password))
            assert.NoError(t, err)
        })

        user, err := service.Create(dto)

        assert.NoError(t, err)
        assert.NotNil(t, user)
        repo.AssertExpectations(t)
    })
}
```

#### Repository Tests

- **Integration Tests**: Repository tests are integration tests that connect to a real database.
- **Scaffolding**: Use `go-resource-scaffolder` to generate the boilerplate for these tests.
- **Test Database**: Use Docker Compose to spin up an isolated PostgreSQL instance for testing.
- **TestMain Setup**:
  - Start Docker container using `docker compose up -d --wait`.
  - Run migrations using `golang-migrate`.
  - Create database connection pool.
  - Run tests.
  - Teardown: close connections and stop Docker container.
- **Test Isolation**: Truncate tables between tests using a `truncateTables()` helper function.
- **Short Mode**: Skip integration tests when running with `-short` flag.
- **Test Coverage**: Test success cases, constraint violations (e.g., duplicate email), invalid inputs, and not found scenarios.

**Example**:

```go
func TestMain(m *testing.M) {
    ctx := context.Background()

    // Start Docker container
    cmd := exec.Command("docker", "compose", "-f", "../../docker/docker-compose.test.yaml", "up", "-d", "--wait")
    if err := cmd.Run(); err != nil {
        log.Fatalf("Could not start testing database: %v", err)
    }

    // Run migrations
    cmd = exec.Command("migrate", "-path", "./../../postgres/migrations", "-database", connStr, "up")
    if err := cmd.Run(); err != nil {
        log.Fatalf("Could not migrate the database: %v", err)
    }

    // Setup database connection
    testDB, _ = pgxpool.New(ctx, connStr)

    // Run tests
    code := m.Run()

    // Teardown
    testDB.Close()
    exec.Command("docker", "compose", "-f", "../../docker/docker-compose.test.yaml", "down").Run()
    os.Exit(code)
}

func truncateTables(ctx context.Context, db *pgxpool.Pool) {
    tables := []string{"users"}
    for _, table := range tables {
        db.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table))
    }
}
```

### Mocking Patterns

- **Mock Location**: All mocks are centralized in `internal/mocks/`.
- **Interface Compliance**: Mocks verify interface compliance using `var _ InterfaceName = (*MockName)(nil)`.
- **Testify/Mock**: Use `github.com/stretchr/testify/mock` for mock implementations.
- **Return Handling**: Check if return value is not nil before type assertion to avoid panics.
- **Naming Convention**: Mocks are named with the `Mock` suffix (e.g., `UsersServiceMock`, `UsersRepositoryMock`).

**Example**:

```go
type UsersServiceMock struct {
    mock.Mock
}

var _ domain.UsersService = (*UsersServiceMock)(nil)

func (m *UsersServiceMock) GetByUUID(uuid string) (*domain.User, error) {
    args := m.Called(uuid)
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
- **Enums**: Use typed constants for enums (e.g., `AuthMethod` with values like `AuthMethodEmail`, `AuthMethodGoogle`).

### General Best Practices

- **Error Messages**: Use dot-separated keys for error messages (e.g., `"user.create.failed"`) to support internationalization.
- **Pointer Usage**: Services and repositories accept and return pointers to avoid unnecessary copying.
- **Dependency Injection**: All dependencies are injected via constructors, never created inside the dependent struct. Shared instances are built once in the composition root (`internal/factories/dependencies.go`), not re-created per factory.
- **Interface-Driven Design**: Program to interfaces, not implementations. This allows easy mocking and testing.
- **Zero Comments**: The code is self-documenting; avoid comments unless explaining complex business logic.
- **Exact Errors**: Don't wrap errors unnecessarily; return them as-is unless adding valuable context.
