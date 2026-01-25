# Error Handling Architecture

This document describes the error handling strategy implemented in the project. The architecture follows a strict 3-layered pattern where errors are transformed at the boundaries to ensure clean separation of concerns.

## Error Handling Philosophy

### Layer Responsibilities & Trust Chain

```
Repository → Service → Controller → HTTP Response
   │            │           │
   │            │           └─ HandleError() maps domain errors to HTTP status
   │            │
   │            └─ Trusts repo errors, only creates domain errors for:
   │               • Business validation (e.g., password too short)
   │               • External services (e.g., email provider failed)
   │               • Orchestration logic (e.g., user can't delete own account)
   │
   └─ Transforms infrastructure errors (pgx, pgconn) → domain errors
```

**Key principles:**

1.  **Repository layer**: Maps **infrastructure errors** → **domain errors**
    - `pgx.ErrNoRows` → `domain.NotFoundError`
    - `pgconn.PgError` (code 23505) → `domain.ConflictError`
    - Unknown DB errors → `domain.InternalServerError`

2.  **Service layer**: Handles **business logic errors** + propagates repo errors
    - Validation failures → `domain.ValidationError`
    - Authorization logic → `domain.UnauthorizedError`
    - Pass-through repository domain errors **unchanged** (no re-wrapping)

3.  **Controller layer**: Maps **domain errors** → **HTTP responses**
    - Uses `errors.As()` to detect error type
    - Calls `api.HandleError(ctx, w, err)` — no manual status code selection
    - Unknown errors default to 500 Internal Server Error

## Domain Error Types

Defined in `internal/domain/errors.go`, these types represent **what** went wrong, independent of **how** it is presented.

| Error Type            | HTTP Status | Description                                      |
| :-------------------- | :---------- | :----------------------------------------------- |
| `NotFoundError`       | 404         | Resource not found (e.g., User not found)        |
| `ValidationError`     | 400         | Invalid input (supports field-level details)     |
| `ConflictError`       | 409         | State conflicts (e.g., Email already exists)     |
| `UnauthorizedError`   | 401         | Authentication/Authorization failures            |
| `InternalServerError` | 500         | Unexpected system failures. Wraps original error |

## Implementation Details

### 1. Repository Layer (`internal/repositories/`)

Repositories catch database-specific errors and return `domain` errors. We use helper functions in `internal/repositories/helpers.go` to standardize this mapping.

**Helper Functions:**

- `isNoRowsError(err, message)`: Checks for `pgx.ErrNoRows`.
- `isConflictError(err, message)`: Checks for PostgreSQL error code `23505` (Unique Violation).
- `isForeignKeyViolationError(err, message)`: Checks for PostgreSQL error code `23503` (Foreign Key Violation).

**Example:**

```go
func (r *UsersPostgresRepository) FindByEmail(email string) (*domain.User, error) {
    user, err := r.q.GetUserByEmail(context.Background(), email)
    if err != nil {
        if noRowsErr := isNoRowsError(err, "users.notFound"); noRowsErr != nil {
            return nil, noRowsErr
        }
        return nil, domain.NewInternalServerError("users.internalServerError", err)
    }
    // ...
}
```

### 2. Service Layer (`internal/services/`)

Services handle business logic validation and propagate repository errors.

**Example:**

```go
func (s *usersService) Create(dto domain.CreateUserDTO) (*domain.User, error) {
    // Business Validation
    if dto.Password == "" {
        return nil, domain.NewValidationError("password.required",
            map[string]string{"password": "Password is required"},
        )
    }

    // Propagate Repository Errors
    return s.repo.Create(user)
}
```

### 3. Controller Layer (`internal/controllers/`)

Controllers delegate error handling to the centralized `api.HandleError` function.

**Example:**

```go
func (c *UsersController) Create(w http.ResponseWriter, r *http.Request) {
    // ...
    user, err := c.service.Create(dto)
    if err != nil {
        api.HandleError(r.Context(), w, err)
        return
    }
    // ...
}
```

### 4. API Layer (`internal/api/errors.go`)

The `HandleError` function inspects the error type using `errors.As()` and writes the appropriate JSON response.

**Response Format:**

```json
{
  "error": "validation_error_message",
  "details": {
    "field_name": "error description"
  }
}
```

## Error Logging & Observability

We use a **Canonical Log Line** pattern to ensure observability without log spam.

### How it works

1.  **Context Injection**:
    When `api.HandleError(ctx, w, err)` is called, it injects the error into the request context via `api.RequestContextData`.

    ```go
    // internal/api/errors.go
    if hasReqContextData {
        reqContextData.Error = err
    }
    ```

2.  **Middleware Logging**:
    The `LoggerMiddleware` wraps the entire request. When the request finishes, it reads the error from the context and logs it alongside the request metadata.
    ```go
    // internal/middlewares/logger_middleware.go
    if reqContextData.Error != nil {
        attrs = append(attrs, slog.String("error", reqContextData.Error.Error()))
    }
    ```

### Benefits

- **Root Cause Visibility**: The `InternalServerError` type wraps the original infrastructure error (e.g., PostgreSQL connection failure), so the log entry contains the actual cause of the failure.
- **Single Log Entry**: Access logs and error logs are combined, making it easy to correlate HTTP status codes with their underlying errors.
- **Contextual**: Every error is automatically associated with the `request_id` and `user_id`.
