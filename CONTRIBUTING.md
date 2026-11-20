# Contributing to Go net/http Auth Base

Thank you for your interest in contributing to this project! I welcome contributions from the community. Please take a moment to review this document to ensure a smooth contribution process.

## 🏗️ Architecture

This project follows a clean, layered architecture. Understanding this structure is crucial for contributing effectively.

```ascii
+---------------------------------------------------------------------------+
|                                HTTP Layer                                 |
|                                                                           |
|  Global chain: requestContextData -> requestUUID -> telemetry -> logger   |
|                -> cors -> rateLimit -> mux                                |
|  Per route:    auth (access token) -> role (admin)                        |
|                                                                           |
|  +-----------------+ +-----------------+ +-----------------+              |
|  | UsersController | | AuthController  | | AuditController |              |
|  +--------+--------+ +--------+--------+ +--------+--------+              |
|  (+ DocsController: Swagger UI, HealthController: /health, /ready)        |
+-----------|-------------------|-------------------|-----------------------+
            |                   |                   |
+-----------v-------------------v-------------------v-----------------------+
|                               Service Layer                               |
|                                                                           |
|  UsersService <------------ AuthService           AuditService            |
|       |                        |                                          |
|       |                        +----> PendingSignupService               |
|       v                        v              |                           |
|  EmailVerificationService <-------------------+                           |
|       |                        |                                          |
|       +-------------------> TokenService (JWT)                            |
+-----------|-------------------|-------------------|-----------------------+
            |                   |                   |
+-----------v-------------------v-------------------v-----------------------+
|                      Data Access Layer (Repositories & Providers)         |
|                                                                           |
|  UsersRepository  AuthRepository  SessionsRepository  AuditRepository     |
|  PendingSignupRepository  EmailSendLimiter  StepUpRepository              |
|  Transactor (WithinTx)            OAuthProviders      EmailProvider       |
+-----------|---------------------------|-------------------|---------------+
            v                           v                   v
   +-----------------+        +------------------+   +-----------------+
   |   PostgreSQL    |        |  OAuth providers |   |  Resend (email) |
   +-----------------+        +------------------+   +-----------------+

All of the above is built once by factories.NewDependencies (composition root)
and wired into the controllers by thin per-controller factories.
```

### Architecture Overview

The project implements a **Clean Architecture** inspired pattern, structured into three main layers:

1.  **HTTP Layer (Controllers & Middlewares)**:
    - **Controllers**: Handle incoming HTTP requests, validate input (DTOs), and format responses. They act as the entry point and delegate business logic to services.
    - **Middlewares**: Handle cross-cutting concerns like authentication, logging, and CORS.

2.  **Service Layer (Business Logic)**:
    - Contains the core business rules and logic.
    - Orchestrates operations between repositories and other services.
    - Decoupled from HTTP concerns and database implementation details.

3.  **Data Access Layer (Repositories & Providers)**:
    - **Repositories**: Abstract the database interactions. We use `sqlc` to generate type-safe Go code from SQL queries.
    - **Providers**: Handle interactions with external services (OAuth providers like Google, GitHub and Microsoft; email through Resend).

**Key Principles**:

- **Dependency Inversion**: High-level modules (Controllers) depend on abstractions (Interfaces defined in `internal/domain`), not concrete implementations.
- **Domain-Centric**: The `internal/domain` package defines the core entities and interfaces, serving as the contract between layers.
- **Dependency Injection**: `factories.NewDependencies` builds the shared repositories, services and middlewares once, and `cmd/main.go` passes them to thin per-controller factories, ensuring loose coupling and testability.

The reasoning behind these choices is recorded in the [Architecture Decision Records](docs/adr/README.md). [AGENTS.md](AGENTS.md) is the most detailed description of the conventions (written for AI agents, but useful for humans too).

## 💻 Code Standards and Conventions

- **Language**: Go 1.26+
- **Style**: Follow standard Go formatting (`gofmt`).
- **Linter**: We use `golangci-lint`. Ensure your code passes all lint checks.
- **Architecture**: Respect the layered architecture.
  - **Controllers**: Handle HTTP requests, validation, and response formatting.
  - **Services**: Contain business logic.
  - **Repositories**: Handle database interactions.
  - **Domain**: Define interfaces and core entities.
- **Dependency Injection**: Use the `factories` package to wire dependencies.
- **Errors**: Return the typed domain errors and let `api.HandleError` pick the status code (see [docs/ERRORS.md](docs/ERRORS.md)).
- **Context**: `context.Context` is the first argument of every service and repository method, from `r.Context()` down to the database.
- **Comments**: Only swag annotations on handlers and comments that explain complex business logic.
- **API Docs**: After changing handler annotations, run `make swagger-gen` and commit `docs/swagger/` (CI fails on drift).
- **Schema**: While this is still a template, schema changes go into `000001_init_db.up.sql`/`.down.sql` instead of new migration files.

## 🧭 Architecture Decision Records

Write an ADR in `docs/adr/` in the same PR when a decision changes or adds a convention, adds or replaces an infrastructure dependency, changes the security model, or is hard to reverse. Local choices (naming, a helper, a behavior-preserving refactor) do not need one. See [docs/adr/README.md](docs/adr/README.md) for the format and the rules (accepted ADRs are never rewritten, only superseded).

## 🛠️ Scaffolding Tools

To help you follow the project's architecture and conventions, we provide scaffolding scripts. These are the same tools used by our AI agents.

### Create a New Resource

To generate a complete vertical slice (Domain, Repository, Service, Controller, Factory, and Tests):

```bash
npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName>
# Example: npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts Product
```

### Create a Migration

To generate migration files and a corresponding query file:

```bash
npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts <migration_name>
# Example: npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts add_products_table
```

## 📝 Commit Message Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

Format: `<type>(<scope>): <description>`

Examples:

- `feat(auth): add google oauth provider`
- `fix(user): fix password validation logic`
- `docs(readme): update installation instructions`
- `test(service): add unit tests for user service`

## 🧪 Testing Requirements

- **Coverage**: We aim for **80%+ test coverage**.
- **Unit Tests**: Write unit tests for all new services and controllers.
- **Integration Tests**: Repository tests run against a real PostgreSQL started by testcontainers (`postgres.NewTestPool`), so a running Docker daemon is required. Each transactional flow needs a test that forces a failure and asserts nothing was persisted.
- **Naming**: One `Test<Type>_<Method>` per method, with scenarios as `t.Run` subtests.
- **Running Tests**:
  ```bash
  go test ./...          # all tests
  go test -short ./...   # skip integration tests
  make show-cover        # coverage report, as posted by CI
  ```

## 🔄 Pull Request Process

1.  **Fork the repository** and create your branch from `main`.
2.  **Install dependencies**: Run `make setup`.
3.  **Make your changes** following the code standards.
4.  **Add tests** for your changes.
5.  **Run tests** to ensure everything is working: `go test ./...`.
6.  **Run linter** (`golangci-lint run`, if available locally) or check CI status.
7.  **Update docs**: `make swagger-gen` for handler changes, an ADR for architectural decisions, and README/AGENTS.md when a convention or command changes.
8.  **Commit your changes** using the conventional commit format.
9.  **Push to your fork** and submit a Pull Request.
10. **Description**: Provide a clear description of your changes and link to any relevant issues.

## ⚙️ Development Setup

Please refer to the [Getting Started](README.md#-getting-started) section in the `README.md` for detailed instructions on how to set up the project locally, run the database, and start the application.

Thank you for contributing!
