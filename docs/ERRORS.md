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
   │               • Business rules (e.g., only self or admin can access a user)
   │               • External services (e.g., OAuth user info fetch failed)
   │               • Orchestration logic (e.g., OAuth state/provider mismatch)
   │
   └─ Transforms infrastructure errors (pgx, pgconn) → domain errors
```

**Key principles:**

1.  **Repository layer**: Maps **infrastructure errors** → **domain errors**
    - `pgx.ErrNoRows` → `domain.NotFoundError`
    - `pgconn.PgError` (code 23505) → `domain.ConflictError`
    - Unknown DB errors → `domain.InternalServerError`

2.  **Service layer**: Handles **business logic errors** + propagates repo errors
    - Business validation failures → `domain.ValidationError`
    - Authentication failures → `domain.UnauthorizedError`
    - Authorization failures (e.g. `Actor.CanAccess`) → `domain.ForbiddenError`
    - Pass-through repository domain errors **unchanged** (no re-wrapping)

3.  **Controller layer**: Maps **domain errors** → **HTTP responses**
    - Input decoding/validation via `api.DecodeAndValidate[T](r)` → `domain.ValidationError`
    - Calls `api.HandleError(ctx, w, err)` — no manual status code selection
    - `HandleError` uses `errors.As()` to detect the error type; unknown errors default to 500 Internal Server Error

## Domain Error Types

Defined in `internal/domain/errors.go`, these types represent **what** went wrong, independent of **how** it is presented.

| Error Type            | HTTP Status | Description                                      |
| :-------------------- | :---------- | :----------------------------------------------- |
| `NotFoundError`       | 404         | Resource not found (e.g., User not found)        |
| `ValidationError`     | 400         | Invalid input (supports field-level details)     |
| `ConflictError`       | 409         | State conflicts (e.g., Email already exists)     |
| `UnauthorizedError`   | 401         | Authentication failures (missing/invalid token, bad credentials) |
| `ForbiddenError`      | 403         | Authenticated but not allowed (e.g., not self or admin, missing role) |
| `InternalServerError` | 500         | Unexpected system failures. Wraps original error |

## Implementation Details

### 1. Repository Layer (`internal/repositories/`)

Repositories catch database-specific errors and return `domain` errors. We use helper functions in `internal/repositories/helpers.go` to standardize this mapping.

**Helper Functions:**

- `isNoRowsError(err, message)`: Checks for `pgx.ErrNoRows`.
- `isConflictError(err, message)`: Checks for PostgreSQL error code `23505` (Unique Violation).
- `isForeignKeyViolationError(err, message)`: Checks for PostgreSQL error code `23503` (Foreign Key Violation).
- `parseUUID(uuidStr, message)`: Converts a string to `pgtype.UUID`, returning a domain error for invalid input.

**Example:**

```go
func (r *UsersPostgresRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
    user, err := r.q.GetUserByEmail(ctx, email)
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

Services handle business rules and propagate repository errors unchanged. Input shape (required fields, email format, password length) is already validated by the controller through `validate` struct tags.

**Example:**

```go
var errForbiddenUserAccess = domain.NewForbiddenError("users.forbidden")

func (s *usersService) GetByUUID(ctx context.Context, actor domain.Actor, uuid string) (*domain.User, error) {
    // Business rule
    if !actor.CanAccess(uuid) {
        return nil, errForbiddenUserAccess
    }

    // Propagate Repository Errors
    return s.repo.FindByUUID(ctx, uuid)
}
```

### 3. Controller Layer (`internal/controllers/`)

Controllers decode and validate input with `api.DecodeAndValidate[T]` (strict JSON: unknown fields and trailing data are rejected; then the `validate` struct tags run) and delegate every error to the centralized `api.HandleError` function.

**Example:**

```go
func (c *UsersController) CreateUser(w http.ResponseWriter, r *http.Request) {
    dto, err := api.DecodeAndValidate[domain.CreateUserDTO](r)
    if err != nil {
        api.HandleError(r.Context(), w, err)
        return
    }

    user, err := c.userService.Create(r.Context(), dto)
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
  "data": null,
  "error": "request.validation_failed",
  "details": {
    "field_name": "error description"
  }
}
```

`error` is always a dot-separated message key. For a `500`, the body only carries the key (e.g. `users.internalServerError`), never the wrapped cause.

## Error Logging & Observability

We use a **Canonical Log Line** pattern to ensure observability without log spam.

### How it works

1.  **Context Injection**:
    When `api.HandleError(ctx, w, err)` is called, it stores the error in the request's `shared.RequestContextData` (put in the context by `RequestContextDataMiddleware`). For an `InternalServerError` it stores the unwrapped cause.

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
- **Contextual**: Every error is automatically associated with the `requestUUID` and `userUUID` of the request log line.
- **Traces**: When telemetry is enabled, `TelemetryMiddleware` also records the stored error on the request span as an `exception` event.
