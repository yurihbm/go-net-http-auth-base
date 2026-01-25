# Project's Errors Refactor

Based on the project structure and the requirements in `TODO.md`, here is the plan to implement **Section 2.1: Custom Error Handling**.

---

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

1. **Repository layer**: Maps **infrastructure errors** → **domain errors**
   - `pgx.ErrNoRows` → `domain.NotFoundError`
   - `pgconn.PgError` (code 23505) → `domain.ConflictError`
   - Unknown DB errors → `domain.InternalServerError`

2. **Service layer**: Handles **business logic errors** + propagates repo errors
   - Validation failures → `domain.ValidationError`
   - Authorization logic → `domain.UnauthorizedError`
   - Pass-through repository domain errors **unchanged** (no re-wrapping)

3. **Controller layer**: Maps **domain errors** → **HTTP responses**
   - Uses `errors.As()` to detect error type
   - Calls `HandleError(w, err)` — no manual status code selection
   - Unknown errors default to 500 Internal Server Error

### Why Handle Errors at Both Repository and Service Layers?

Handling only at the service layer leaks infrastructure details:

```go
// BAD: Service has to know about pgx (infrastructure leak)
if errors.Is(err, pgx.ErrNoRows) { ... }

// GOOD: Service only sees domain errors (clean abstraction)
if errors.As(err, &domain.NotFoundError{}) { ... }
```

This creates a clean boundary where infrastructure concerns don't leak into business logic.

### Go Conventions for Error Handling

1. **Don't over-wrap** — only add context when it adds value
2. **Use `errors.Is()` and `errors.As()`** — standard library pattern for error inspection
3. **Keep error types in domain** — they're part of your business contracts
4. **Log at boundaries** — typically in controllers or middleware, not every layer

---

## Error Sources: sqlc vs pgx

### Understanding the Stack

```
┌─────────────┐     generates     ┌─────────────┐     uses      ┌─────────────┐
│    sqlc     │ ───────────────► │  Go code    │ ────────────► │  pgx/pgconn │
│  (compile)  │                  │  (runtime)  │               │  (driver)   │
└─────────────┘                  └─────────────┘               └─────────────┘
                                                                     │
                                                                     ▼
                                                               ┌─────────────┐
                                                               │ PostgreSQL  │
                                                               └─────────────┘
```

**sqlc is purely a code generator** — it has no runtime component:

- Parses `.sql` files
- Generates type-safe Go functions and structs
- Outputs code that calls the configured driver (`pgx/v5`)
- **Does NOT** provide error types, wrap driver errors, or run at runtime

**All errors come from the driver:**

- `github.com/jackc/pgx/v5` — Go-level errors like `ErrNoRows`
- `github.com/jackc/pgx/v5/pgconn` — PostgreSQL protocol errors (`PgError`)

### Error Documentation Sources

1. **pgx driver errors**: https://pkg.go.dev/github.com/jackc/pgx/v5#pkg-variables
   - Key error: `pgx.ErrNoRows` for empty query results

2. **PostgreSQL error codes** (via pgconn): https://www.postgresql.org/docs/current/errcodes-appendix.html
   - `23505` — unique_violation (duplicate key)
   - `23503` — foreign_key_violation
   - `23502` — not_null_violation
   - `23514` — check_violation

3. **pgconn.PgError struct**: https://pkg.go.dev/github.com/jackc/pgx/v5/pgconn#PgError
   - `Code` — PostgreSQL error code
   - `Message` — Primary error message
   - `ConstraintName` — Which constraint failed
   - `TableName`, `ColumnName` — Context about the failure

---

## Implementation Plan

### 1. Domain Layer: Define Semantic Errors

**File:** `internal/domain/errors.go` (Create)

Define custom error types that represent **what** went wrong, independent of **how** it is presented (HTTP status codes). This decouples your business logic from the transport layer.

- **Base Error Interface/Struct:** Create a common behavior for all domain errors, potentially supporting error wrapping (`Unwrap()`).
- **Specific Error Types:** Implement the types requested in the TODO.
  - `NotFoundError`: For missing resources (e.g., User not found).
  - `ValidationError`: For invalid input (e.g., invalid email format). Should support field-level details.
  - `ConflictError`: For state conflicts (e.g., Email already exists).
  - `UnauthorizedError`: For authentication failures.
  - `InternalServerError`: For unexpected system failures (DB down, etc.).

**Example Pattern:**

```go
type AppError struct {
    Code    string // Machine-readable code (e.g., "user_not_found")
    Message string // Human-readable message
    Err     error  // Underlying error (for internal logging)
}
// Implement error interface...
```

### 2. API Layer: Centralized Error Mapping

**File:** `internal/api/errors.go` (Create)

Create a centralized helper to map `domain` errors to HTTP responses. This ensures consistency across all controllers.

- **Function:** `HandleError(w http.ResponseWriter, err error)`
- **Logic:**
  1.  Use `errors.As` or type switches to detect the specific `domain` error type.
  2.  Map the error type to the appropriate HTTP Status Code:
      - `NotFoundError` -> `404 Not Found`
      - `ValidationError` -> `400 Bad Request`
      - `ConflictError` -> `409 Conflict`
      - `UnauthorizedError` -> `401 Unauthorized`
      - Default/Unknown -> `500 Internal Server Error`
  3.  Construct the `ResponseBody` with the error message and code.
  4.  Call `WriteJSONResponse`.

### 3. Repository Layer: Map Infrastructure Errors

**Files:** `internal/repositories/*.go`

Update repositories to catch database-specific errors (like `pgx.ErrNoRows` or `pgconn.PgError`) and return `domain` errors. This ensures that the service layer only deals with domain-agnostic errors.

#### HOW TO: Handle Errors with sqlc and pgx

When working with `sqlc` and `pgx/v5`, you need to handle specific error types returned by the driver.

**1. Import necessary packages:**

```go
import (
	"errors"

	"go-net-http-auth-base/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)
```

**2. Handle `pgx.ErrNoRows`:**

When a query expects a single row but finds none, `pgx` returns `pgx.ErrNoRows`. This should be mapped to `domain.NotFoundError`.

```go
if errors.Is(err, pgx.ErrNoRows) {
    return nil, domain.NewNotFoundError("user.not_found")
}
```

**3. Handle Unique Constraint Violations:**

PostgreSQL returns specific error codes for constraint violations. Use `errors.As` to cast the error to `*pgconn.PgError` and check the `Code` field. Code `23505` represents a unique constraint violation (e.g., duplicate email).

```go
var pgErr *pgconn.PgError
if errors.As(err, &pgErr) && pgErr.Code == "23505" {
    return nil, domain.NewConflictError("user.email_already_exists")
}
```

**4. Complete Example:**

Here is how a `GetByEmail` method should look:

```go
func (r *UsersPostgresRepository) FindByEmail(email string) (*domain.User, error) {
    user, err := r.q.GetUserByEmail(context.Background(), email)
    if err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, domain.NewNotFoundError("user.not_found")
        }
        return nil, err // Let the controller/service handle unexpected system errors
    }

    domainUser := toDomainUser(user)
    return &domainUser, nil
}
```

**5. Example for Create (Handling Conflicts):**

```go
func (r *UsersPostgresRepository) Create(user domain.User) (*domain.User, error) {
    // ... setup params ...
    createdUser, err := r.q.CreateUser(context.Background(), params)
    if err != nil {
        var pgErr *pgconn.PgError
        if errors.As(err, &pgErr) && pgErr.Code == "23505" {
            return nil, domain.NewConflictError("user.exists")
        }
        return nil, err
    }
    // ...
}
```

### 4. Service Layer: Return Domain Errors

**Files:** `internal/services/*.go`

Update services to return `domain` errors for business logic failures.

- **Validation:** Return `domain.ValidationError` if input validation fails (e.g., password too short).
- **Propagation:** Pass through errors returned by the repository layer (since they are already domain errors).

### 5. Controller Layer: Simplify Handlers

**Files:** `internal/controllers/*.go`

Refactor controllers to remove manual status code selection.

- **Current:**
  ```go
  if err != nil {
      api.WriteJSONResponse(w, http.StatusNotFound, ...) // Manual mapping
      return
  }
  ```
- **New:**
  ```go
  if err != nil {
      api.HandleError(w, err) // Automatic mapping
      return
  }
  ```

### 6. Response Structure Update

**File:** `internal/api/response.go`

Enhance `ResponseBody` to support structured error details, especially for validation.

- **Add Field:** `Details map[string]any` (or similar) to the `ResponseBody` or a specific `ErrorResponse` struct to hold field-specific validation errors (e.g., `{"email": "invalid format"}`).

### 7. Testing & Documentation

- **Tests:** Add unit tests for `HandleError` to ensure correct mapping. Update Controller tests to mock domain errors and assert correct HTTP statuses.
- **Docs:** Update Swagger/OpenAPI docs to list the standard error codes returned by endpoints.
