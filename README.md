# Go net/http Auth Base

[![Test](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/test.yml/badge.svg)](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/test.yml)
[![Lint](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/lint.yml/badge.svg)](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/lint.yml)

A clean, modular Go backend service template. Built with the standard `net/http`
library and focused on maintainability, testability, and following clean architecture
principles. This project comes with users CRUD, email verification, email/password and
OAuth (Google, GitHub, Microsoft) login with per-device refresh sessions, audit logs,
admin-only Swagger UI and OpenTelemetry observability.

## 📂 Project Structure

The project follows a layered architecture pattern. For a detailed explanation of the logical architecture and design principles, please see [CONTRIBUTING.md](CONTRIBUTING.md#-architecture). The reasoning behind the key decisions (architecture, error handling, database, observability and security) is recorded in the [Architecture Decision Records](docs/adr/README.md).

### Directory Layout

```
go-net-http-auth-base/
├── cmd/
│   └── main.go         # Entry point: config, telemetry, DB pool, routes, middleware chain
├── config/             # Environment variable loading and validation
├── internal/           # Private application code
│   ├── api/            # Request decoding/validation, responses, error mapping, cookies
│   ├── controllers/    # HTTP handlers (and Swagger UI assets)
│   ├── services/       # Business logic
│   ├── repositories/   # Data access layer
│   ├── providers/      # External services (OAuth providers, email)
│   ├── domain/         # Core entities, DTOs, errors and interfaces
│   ├── factories/      # Composition root (dependency injection)
│   ├── middlewares/    # HTTP middlewares
│   ├── mocks/          # testify mocks of the domain interfaces
│   ├── infra/          # Audit log partition manager
│   ├── logger/         # slog setup
│   ├── telemetry/      # OpenTelemetry SDK bootstrap
│   ├── shared/         # Request context data
│   └── env/            # Typed environment variable lookups
├── postgres/           # Database layer
│   ├── migrations/     # Database migrations
│   ├── queries/        # SQL queries for sqlc
│   └── *.go            # Generated code, connection, query tracers, test helper
├── docker/             # Dockerfile, compose files and Grafana dashboards
└── docs/               # ADRs, Swagger spec, error and audit docs
```

## 🛠️ Tech Stack

- **Language**: Go 1.26
- **Database**: PostgreSQL 18
- **HTTP Router**: Standard library `net/http`
- **Database Driver**: `pgx/v5`
- **Authentication**: JWT (`golang-jwt/jwt`) in `HttpOnly` cookies, OAuth 2.0 with PKCE (`golang.org/x/oauth2`)
- **Validation**: `go-playground/validator`
- **Password Hashing**: `bcrypt` (`golang.org/x/crypto`)
- **Migrations**: `golang-migrate/migrate`
- **Query Generation**: `sqlc` (type-safe Go from SQL)
- **API Docs**: `swaggo/swag` (Swagger 2.0) and `http-swagger`
- **Observability**: `log/slog`, OpenTelemetry (OTLP/HTTP), Grafana LGTM for development
- **Email**: Resend (logs the email in development)
- **Development**: `air` (live reload)
- **Testing**: `testify`, `testcontainers-go`

## 🚀 Getting Started

### Prerequisites

- Go 1.26 or higher
- Docker and Docker Compose
- Make

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd go-net-http-auth-base
   ```

2. **Rename base module (optional)**

   ```bash
   # On Linux:
   find . -type f -not -path './.git/*' -exec sed -i 's/go-net-http-auth-base/{NEW_BASE_MODULE_NAME}/g' {} +
   # On Mac:
   find . -type f -not -path './.git/*' -exec sed -i '' 's/go-net-http-auth-base/{NEW_BASE_MODULE_NAME}/g' {} +
   ```

   Replace `{NEW_BASE_MODULE_NAME}` with the desired name for the project.

3. **Install development tools**

   ```bash
   make setup
   ```

   This installs the pinned versions of `air`, `sqlc`, `migrate` and `swag`, and runs `go mod tidy`.

4. **Configure environment**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` with your configuration. `JWT_SECRET` (at least 32 characters) and `DATABASE_URL` are required; see the Configuration section below for the rest.

5. **Start the database**

   ```bash
   docker compose --env-file .env -f docker/docker-compose.dev.yaml up -d
   ```

6. **Run migrations**

   ```bash
   make migrate-up
   ```

7. **Start the development server**

   ```bash
   air
   ```

   The server will start on `http://localhost:8080` (if API_PORT is not set) with live reload enabled.

## 📝 Available Commands

### Development

```bash
air             # Run with live reload (development)
make setup      # Install all required tools for development
make build      # Build production binary (outputs to bin/app)
make tidy       # Tidy go.mod and go.sum
```

### Database

```bash
make migrate-up                             # Apply all pending migrations
make migrate-down                           # Rollback last migration
make migrate-create name=migration_name     # Create new migration files
make sqlc-gen                               # Generate Go code from SQL queries
```

### API Docs

```bash
make swagger-gen    # Regenerate docs/swagger/ from the handler annotations
```

The spec is generated by [swag](https://github.com/swaggo/swag) (Swagger 2.0) from the doc comments on the handlers and committed under `docs/swagger/`; CI fails if it is out of date.

Swagger UI is served at `http://localhost:8080/swagger/index.html` (spec at `/swagger/doc.json`) in every environment, but only for authenticated admins. Open `http://localhost:8080/swagger/`: it is a public login gate that sends you straight to the UI if you already have an admin session (refreshing it when possible) and otherwise shows an email/password form that signs in through `POST /auth/login`. Non-admin users get an access-denied message. Authentication is cookie-based, so the `access_token` cookie it sets is sent by the browser on both the UI and "Try it out" requests. The access token lasts 15 minutes; when it expires, reload `/swagger/` to refresh the session or sign in again. The UI top bar has a Logout button, and executing `POST /auth/logout` through "Try it out" also returns you to the login gate.

### Testing

```bash
go test ./...                    # Run all tests (integration tests need Docker)
go test -short ./...             # Skip the integration tests
go test ./... -v                 # Run with verbose output
go test ./... -cover             # Run with coverage report
make test-cover                  # Coverage without generated and wiring packages (writes coverage.out)
make show-cover                  # test-cover plus the per-function report CI posts on PRs
```

## 🌐 API Endpoints

Every response uses the [standard format](#api-response-format). Authenticated endpoints read the `access_token` cookie set by login.

| Method   | Path                          | Auth  | Description                                                         |
| -------- | ----------------------------- | ----- | ------------------------------------------------------------------- |
| `POST`   | `/users`                      | -     | Sign up with email and password, and send the verification email    |
| `POST`   | `/users/verify-email`         | -     | Verify the email with the token from the email link                 |
| `POST`   | `/users/resend-verification`  | -     | Resend the verification email (silent for unknown/verified emails)  |
| `POST`   | `/users/confirm-email-change` | -     | Apply an email change with the token from the confirmation link     |
| `GET`    | `/users/me`                   | User  | Current user                                                        |
| `POST`   | `/users/me/email`             | User  | Request an email change (confirmation link sent to the new address) |
| `GET`    | `/users/{uuid}`               | User  | Get a user (self or admin)                                          |
| `PUT`    | `/users/{uuid}`               | User  | Update a user's name (self or admin)                                |
| `DELETE` | `/users/{uuid}`               | User  | Delete a user (self or admin)                                       |
| `POST`   | `/auth/login`                 | -     | Email/password login; sets the `access_token` and `refresh_token` cookies |
| `POST`   | `/auth/refresh`               | -     | Rotate the refresh token (reads the `refresh_token` cookie)        |
| `POST`   | `/auth/logout`                | User  | End the current session                                             |
| `GET`    | `/auth/{provider}/login`      | -     | Start OAuth (`google`, `github`, `microsoft`)                       |
| `GET`    | `/auth/{provider}/callback`   | -     | OAuth callback                                                      |
| `GET`    | `/audit-logs`                 | Admin | List audit logs (filters and cursor pagination)                     |
| `GET`    | `/swagger/`                   | -     | Swagger UI login gate                                               |
| `GET`    | `/swagger/index.html`         | Admin | Swagger UI and spec                                                 |
| `GET`    | `/health`, `/ready`           | -     | Liveness, and readiness (checks the database)                       |

The Swagger UI has the full request and response schemas.

## ⚙️ Configuration

All variables are read and validated once at startup in `config/config.go`; the app refuses to start on a missing required value or a malformed one. `.env.example` is the starting point.

| Variable                                                                 | Default                        | Description                                                                                         |
| ------------------------------------------------------------------------ | ------------------------------ | --------------------------------------------------------------------------------------------------- |
| `API_ENV`                                                                | -                              | `development` (log email provider, non-`Secure` cookies), `production` (JSON logs) or any other value |
| `API_PORT`                                                               | `8080`                         | HTTP port                                                                                           |
| `API_URL`                                                                | -                              | Public base URL, used to build the OAuth redirect URLs (`<API_URL>/auth/<provider>/callback`)       |
| `JWT_SECRET`                                                             | **required**                   | HS256 signing secret, at least 32 characters                                                        |
| `DATABASE_URL`                                                           | **required**                   | PostgreSQL connection string                                                                        |
| `DB_MAX_CONNS`, `DB_MIN_CONNS`                                           | `25`, `5`                      | Pool size                                                                                           |
| `DB_MAX_CONN_LIFETIME`, `DB_MAX_CONN_IDLE_TIME`                          | `1h`, `30m`                    | Connection lifetimes                                                                                |
| `DB_HEALTH_CHECK_PERIOD`, `DB_CONNECT_TIMEOUT`                           | `1m`, `15s`                    | Pool health check and connect timeout                                                               |
| `DB_SLOW_QUERY_THRESHOLD`                                                | `200ms`                        | Queries slower than this are logged                                                                 |
| `DB_STATS_LOG_INTERVAL`                                                  | `30s`                          | Interval of the pool stats log                                                                      |
| `SESSION_MAX_AGE`                                                        | `720h` (30 days)               | Absolute lifetime of a login session (never extended by refreshes)                                  |
| `MAX_SESSIONS_PER_USER`                                                  | `10`                           | Sessions kept per user; the least recently used is evicted                                          |
| `GOOGLE_CLIENT_ID`/`_SECRET`, `GITHUB_CLIENT_ID`/`_SECRET`, `MICROSOFT_CLIENT_ID`/`_SECRET` | -   | OAuth credentials                                                                                   |
| `OAUTH_CALLBACK_ALLOW_LIST`                                              | - (**required** in production) | Comma-separated `redirect_uri` values accepted after OAuth (exact match)                            |
| `CORS_ALLOWED_ORIGINS`, `CORS_ALLOWED_METHODS`                           | -                              | Comma-separated CORS allow lists (exact match)                                                      |
| `RATE_LIMIT_REQUESTS_PER_SECOND`, `RATE_LIMIT_BURST`                     | `20`, `50`                     | Per-IP token bucket                                                                                 |
| `RESEND_API_KEY`, `EMAIL_FROM`                                           | - (**required** outside development) | Resend credentials and sender; without a key, emails are only logged                          |
| `EMAIL_VERIFICATION_URL`                                                 | - (**required** outside development) | Frontend URL that receives the verification token                                             |
| `EMAIL_CHANGE_URL`                                                       | - (**required** outside development) | Frontend URL that receives the email change confirmation token                                |
| `EMAIL_CHANGE_REVERT_URL`                                                | - (**required** outside development) | Frontend URL that receives the "it wasn't me" revert token                                     |
| `OTEL_*`                                                                 | see [Observability](#-observability) | OpenTelemetry export                                                                          |
| `TEST_DB_PORT_START`, `TEST_DB_PORT_END`                                 | `15432`, `15499`               | Host port range for the integration test database container (tests only)                            |

## 🐋 Docker

### Docker for Development

You may use the `docker/docker-compose.dev.yaml` file for development (it does not run the API itself; use `air`). It provides a local Postgres Database (localhost:5432), the pgAdmin application (localhost:5050) and the Grafana LGTM stack (Grafana at http://localhost:3000, default `admin`/`admin`; OTLP gRPC on 4317 and OTLP HTTP on 4318). You should provide a valid .env file.

```bash
docker compose --env-file .env -f docker/docker-compose.dev.yaml up -d --build  # Start services
docker compose -f docker/docker-compose.dev.yaml down                           # Stop services
docker compose -f docker/docker-compose.dev.yaml logs                           # View logs
```

To send traces and metrics to the LGTM stack, set these variables in your `.env`:

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

### Docker for Production

To build and run the application in a production-ready Docker container, you have two options:

#### Option 1: Using Docker Compose (Recommended)

This method automatically sets up the application and a PostgreSQL database.

1. **Create the .env file**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Run with Docker Compose**

   ```bash
   docker compose --env-file .env -f docker/docker-compose.prod.yaml up -d --build
   ```

   The `docker/docker-compose.prod.yaml` file runs an ephemeral service called `migrate` that performs the database migration. When running the migration on a CI/CD pipeline, remove this service.

#### Option 2: Manual Build & Run

1. **Build the image**

   ```bash
   docker build -f docker/Dockerfile -t go-net-http-auth-base .
   ```

2. **Run the container**

   You can pass environment variables using the `--env-file` flag:

   ```bash
   docker run -d \
     -p 8080:8080 \
     --env-file .env \
     --name app \
     go-net-http-auth-base
   ```

   Or pass them individually:

   ```bash
   docker run -d \
     -p 8080:8080 \
     -e DATABASE_URL="postgresql://user:pass@host:5432/db" \
     --name app \
     go-net-http-auth-base
   ```

   Note: When running manually, ensure the `DATABASE_URL` points to a reachable PostgreSQL instance that has the latest migration applied.

## 🗄️ Database

The project uses PostgreSQL with the following tools:

- **Migrations**: Managed with `golang-migrate` in `postgres/migrations/`
- **Query Generation**: SQL queries in `postgres/queries/` are converted to type-safe Go code using `sqlc`
- **Connection Pooling**: Handled by `pgx/v5`

### Schema Changes

While this repository is still a template, schema changes go into `postgres/migrations/000001_init_db.up.sql`/`.down.sql` instead of new migration files (see [ADR-003](docs/adr/ADR-003-database-strategy.md)). Once you bootstrap a real service from it, create new migrations:

```bash
make migrate-create name=add_products_table
```

This creates two files in `postgres/migrations/`:

- `XXXXXX_add_products_table.up.sql` - Forward migration
- `XXXXXX_add_products_table.down.sql` - Rollback migration

### Adding Database Queries

1. Write your SQL in `postgres/queries/*.sql`
2. Run `make sqlc-gen` to generate type-safe Go code
3. Use the generated methods in your repositories

## 🧪 Testing

The project includes tests for all layers:

- **Controller Tests**: Test HTTP handlers and routing with mocked services
- **Service Tests**: Test business logic with mocked dependencies
- **Repository Tests**: Integration tests against a real PostgreSQL

Tests use `testify` for assertions and mocking (mocks live in `internal/mocks/`). Integration tests (`internal/repositories`, `internal/infra`) start a disposable `postgres:18-alpine` container with [testcontainers](https://golang.testcontainers.org/) through `postgres.NewTestPool` and apply the migrations, so they only need a running Docker daemon. `go test -short ./...` skips them.

## 📦 Project Structure Details

### Dependency Injection

The `factories` package is the composition root. `NewDependencies` builds the shared repositories, services and middlewares once, and thin per-controller factories wire them into controllers:

```go
deps, err := factories.NewDependencies(pool, cfg)
// ...
factories.UsersFactory(deps).RegisterRoutes(mux)
factories.AuthFactory(deps, cfg).RegisterRoutes(mux)
```

### API Response Format

All API responses follow a standardized format defined in `internal/api/response.go`:

```jsonc
{
  "data": { ... },      // Success response data (null on errors)
  "message": "...",     // Message key (e.g. "user.create.success")
  "error": "...",       // Error message key (if any)
  "details": { ... },   // Per-field validation errors (if any)
  "meta": { ... }       // Pagination: total, limit, next_cursor
}
```

Messages and errors are dot-separated keys meant for client-side translation. Error types and their HTTP status codes are described in [docs/ERRORS.md](docs/ERRORS.md).

## 📈 Observability

Traces, metrics and logs are exported with OpenTelemetry (OTLP/HTTP) and are disabled by default.

1. Start the Grafana LGTM stack with the dev compose (`docker compose --env-file .env -f docker/docker-compose.dev.yaml up -d lgtm`).
2. Set `OTEL_ENABLED=true` in `.env` (the default endpoint `http://localhost:4318` points at LGTM) and start the API.
3. Open Grafana at http://localhost:3000 (`admin`/`admin`).

Five dashboards are provisioned from `docker/grafana/dashboards/`: **API RED** (rate, errors, duration), **Go runtime**, **Database** (query latency and connection pool), **Logs** and **Request investigation**. **Logs** shows (volume by level, HTTP requests by status, a request table with the error message, an application logs table with the function, file and line that logged, and filterable log panels that append method, path, status, error and call site to each line; the `trace_id` of a row links to Tempo). Each dashboard starts with a row of stat tiles and has a dropdown to jump to the others. **Request investigation** is the per-request view: it starts from the `X-Request-UUID` response header (or a trace ID) and shows the trace waterfall, its database queries and its logs; the `trace_id` links of the Logs dashboard open it. Use the `service` variable to pick the service. The sample dashboards bundled with the `lgtm` image are disabled by overriding its `grafana-dashboards.yaml` provider with `docker/grafana/provisioning/empty.yaml`.

Logs carry `trace_id`/`span_id`, so a trace in Tempo links to its logs in Loki (and a log line links back to its trace).

| Variable                      | Default                     | Description                                   |
| ----------------------------- | --------------------------- | --------------------------------------------- |
| `OTEL_ENABLED`                | `false`                     | Turns on traces, metrics and log export       |
| `OTEL_SERVICE_NAME`           | `go-net-http-auth-base`     | `service.name` reported to the backend        |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4318`     | OTLP/HTTP endpoint                            |
| `OTEL_TRACES_SAMPLER_ARG`     | `1.0`                       | Trace sampling ratio, between 0 and 1         |

## 🔐 Security

- Passwords are hashed using bcrypt
- Short-lived JWTs (15 min access, 7 day refresh) sent only as `HttpOnly`, `SameSite=Strict` cookies (`Secure` outside development); the app refuses to boot with a `JWT_SECRET` shorter than 32 characters
- Server-side, per-device sessions with refresh token rotation and reuse detection; logout ends the current session
- OAuth with PKCE, a state nonce bound to the browser, an exact `redirect_uri` allow list, and account creation/linking only through verified emails
- Self-or-admin authorization on user endpoints, admin-only audit logs and Swagger UI
- Exact-match CORS and per-IP rate limiting
- Audit log of security-relevant actions ([docs/AUDIT.md](docs/AUDIT.md))
- Prepared statements via sqlc to prevent SQL injection

The threat model and the accepted residual risks (for example, access tokens stay valid for up to 15 minutes after logout) are in [ADR-005](docs/adr/ADR-005-security-approach.md).

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions and the process for submitting pull requests. AI agents follow [AGENTS.md](AGENTS.md) (`CLAUDE.md` is a symlink to it).
