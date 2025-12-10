# Contributing to Go net/http Auth Base

Thank you for your interest in contributing to this project! I welcome contributions from the community. Please take a moment to review this document to ensure a smooth contribution process.

## 🏗️ Architecture

This project follows a clean, layered architecture. Understanding this structure is crucial for contributing effectively.

```ascii
+-------------------------------------------------------------------------+
|                               HTTP Layer                                |
|                                                                         |
|   +-------------------+                                                 |
|   |    Middlewares    |                                                 |
|   | (Auth, Logger...) |                                                 |
|   +--------+----------+                                                 |
|            |                                                            |
|            v                                                            |
|   +------------------+      +------------------+   +------------------+ |
|   |  AuthController  |      | UsersController  |   | HealthController | |
|   +--------+---------+      +--------+---------+   +------------------+ |
|            |    |                    |                                  |
+------------|----|--------------------|----------------------------------+
             |    |                    |
             |    v                    v
+------------|------------------------------------------------------------+
|            |               Service Layer                                |
|            |                                                            |
|   +--------v---------+      +------------------+                        |
|   |   AuthService    |----->|   UsersService   |                        |
|   +--------+---------+      +--------+---------+                        |
|            |                         |                                  |
+------------|-------------------------|----------------------------------+
             |                         |
             v                         v
+-------------------------------------------------------------------------+
|                          Data Access Layer                              |
|                                                                         |
|   +------------------+      +------------------+   +------------------+ |
|   |  OAuthProviders  |      |  AuthRepository  |   | UsersRepository  | |
|   +--------+---------+      +--------+---------+   +--------+---------+ |
|            |                         |                      |           |
+------------|-------------------------|----------------------|-----------+
             |                         |                      |
             v                         v                      v
    +------------------+      +---------------------------------------+
    |  External OAuth  |      |              PostgreSQL               |
    |  (Google, etc.)  |      |               Database                |
    +------------------+      +---------------------------------------+
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
    - **Providers**: Handle interactions with external services (e.g., OAuth providers like Google, GitHub).

**Key Principles**:

- **Dependency Inversion**: High-level modules (Controllers) depend on abstractions (Interfaces defined in `internal/domain`), not concrete implementations.
- **Domain-Centric**: The `internal/domain` package defines the core entities and interfaces, serving as the contract between layers.
- **Dependency Injection**: Dependencies are wired up in the `internal/factories` package, ensuring loose coupling and testability.

## 💻 Code Standards and Conventions

- **Language**: Go 1.24+
- **Style**: Follow standard Go formatting (`gofmt`).
- **Linter**: We use `golangci-lint`. Ensure your code passes all lint checks.
- **Architecture**: Respect the layered architecture.
  - **Controllers**: Handle HTTP requests, validation, and response formatting.
  - **Services**: Contain business logic.
  - **Repositories**: Handle database interactions.
  - **Domain**: Define interfaces and core entities.
- **Dependency Injection**: Use the `factories` package to wire dependencies.

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
- **Integration Tests**: Repository tests should run against a real database (using Docker).
- **Running Tests**:
  ```bash
  go test ./... -cover
  ```

## 🔄 Pull Request Process

1.  **Fork the repository** and create your branch from `main`.
2.  **Install dependencies**: Run `make setup`.
3.  **Make your changes** following the code standards.
4.  **Add tests** for your changes.
5.  **Run tests** to ensure everything is working: `go test ./...`.
6.  **Run linter** (if available locally) or check CI status.
7.  **Commit your changes** using the conventional commit format.
8.  **Push to your fork** and submit a Pull Request.
9.  **Description**: Provide a clear description of your changes and link to any relevant issues.

## ⚙️ Development Setup

Please refer to the [Getting Started](README.md#-getting-started) section in the `README.md` for detailed instructions on how to set up the project locally, run the database, and start the application.

Thank you for contributing!
