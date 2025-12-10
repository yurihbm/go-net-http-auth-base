# Go net/http Auth Base

[![Test](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/test.yml/badge.svg)](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/test.yml)
[![Lint](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/lint.yml/badge.svg)](https://github.com/yurihbm/go-net-http-auth-base/actions/workflows/lint.yml)

A clean, modular Go backend service template. Built with the standard `net/http`
library and focused on maintainability, testability, and following clean architecture
principles. This project comes with basic users CRUD and authentication flow with JWT.

## 📂 Project Structure

The project follows a layered architecture pattern. For a detailed explanation of the logical architecture and design principles, please see [CONTRIBUTING.md](CONTRIBUTING.md#-architecture).

### Directory Layout

```
backend/
├── cmd/                # Application entry points
│   └── main.go         # Main application
├── internal/           # Private application code
│   ├── api/            # API response structures
│   ├── controllers/    # HTTP handlers
│   ├── services/       # Business logic
│   ├── repositories/   # Data access layer
│   ├── domain/         # Core entities and interfaces
│   ├── factories/      # Dependency injection
│   ├── providers/      # External services layer
│   └── middlewares/    # HTTP middlewares
├── postgres/           # Database layer
│   ├── migrations/     # Database migrations
│   ├── queries/        # SQL queries for sqlc
│   └── *.go            # Generated code and connection
└── docker/             # Docker configuration
```

## 🛠️ Tech Stack

- **Language**: Go 1.24.5
- **Database**: PostgreSQL 18
- **HTTP Router**: Standard library `net/http`
- **Database Driver**: `pgx/v5`
- **Authentication**: JWT (`golang-jwt/jwt`)
- **Password Hashing**: `bcrypt` (`golang.org/x/crypto`)
- **Migrations**: `golang-migrate/migrate`
- **Query Generation**: `sqlc` (type-safe Go from SQL)
- **Development**: `air` (live reload)
- **Testing**: `testify`

## 🚀 Getting Started

### Prerequisites

- Go 1.24.5 or higher
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

   This installs `air`, `sqlc`, and `migrate` tools.

4. **Configure environment**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` with your configuration.

5. **Start the database**

   ```bash
   docker-compose --env-file .env -f docker/docker-compose.dev.yaml up -d
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

### Testing

```bash
go test ./...                    # Run all tests
go test ./... -v                 # Run with verbose output
go test ./... -cover             # Run with coverage report
```

## 🐋 Docker

### Docker for Development

You may use the `docker/docker-compose.dev.yaml` file for development. It provides a local Postgres Database (localhost:5432) and the pgAdmin application (localhost:5050). You should provide a valid .env file.

```bash
docker compose --env-file .env -f docker/docker-compose.dev.yaml up -d --build  # Start services
docker compose -f docker/docker-compose.dev.yaml down                           # Stop services
docker compose -f docker/docker-compose.dev.yaml logs                           # View logs
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

   The `docker/docker-compose.prod.yaml` file runs a ephemeral service called `migrate` that performs the database migration. When running the migration on a CI/CD pipeline, remove this service.

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

### Creating a New Migration

```bash
make migrate-create name=add_users_table
```

This creates two files in `postgres/migrations/`:

- `XXXXXX_add_users_table.up.sql` - Forward migration
- `XXXXXX_add_users_table.down.sql` - Rollback migration

### Adding Database Queries

1. Write your SQL in `postgres/queries/*.sql`
2. Run `make sqlc-gen` to generate type-safe Go code
3. Use the generated methods in your repositories

## 🧪 Testing

The project includes comprehensive tests for all layers:

- **Controller Tests**: Test HTTP handlers and routing
- **Service Tests**: Test business logic with mocked dependencies
- **Repository Tests**: Test database operations

Tests use `testify` for assertions and mocking.

## 📦 Project Structure Details

### Dependency Injection

The `factories` package handles dependency injection, creating and wiring up components:

```go
factories.UsersFactory(conn).RegisterRoutes(mux)
factories.AuthFactory(conn).RegisterRoutes(mux)
```

### API Response Format

All API responses follow a standardized format defined in `internal/api/response.go`:

```go
{
  "data": { ... },      // Success response data
  "message": "..."      // Response message
  "error": "...",       // Error message (if any)
  "meta": { ... }       // Meta data for paginated responses
}
```

## 🔐 Security

- Passwords are hashed using bcrypt
- JWT tokens for authentication
- Environment variables for sensitive configuration
- Prepared statements via sqlc to prevent SQL injection

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.
