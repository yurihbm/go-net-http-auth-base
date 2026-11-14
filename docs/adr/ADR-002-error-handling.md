# ADR-002: Error Handling Strategy

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Errors cross three layers (repository → service → controller) before they become
an HTTP response. Without a rule:

- infrastructure errors (`pgx.ErrNoRows`, unique violations) leak into services
  and controllers, coupling them to PostgreSQL;
- each handler picks status codes on its own, and they drift;
- internal details (SQL errors, stack context) can end up in response bodies;
- clients get free-form English messages they cannot translate.

## Decision

Transform errors at layer boundaries into a small set of typed domain errors,
and map them to HTTP in exactly one place.

- **Domain error types** (`internal/domain/errors.go`) describe *what* went
  wrong: `NotFoundError` (404), `ValidationError` (400, with per-field
  `details`), `ConflictError` (409), `UnauthorizedError` (401),
  `ForbiddenError` (403) and `InternalServerError` (500, wraps the cause).
- **Repositories** translate infrastructure errors: no rows becomes
  `NotFoundError`, SQLSTATE `23505` becomes `ConflictError`, and anything
  unknown becomes `InternalServerError` wrapping the original error.
- **Services** create domain errors only for business rules and pass repository
  errors through unchanged, without re-wrapping.
- **Controllers** never choose a status code for an error. They call
  `api.HandleError(ctx, w, err)`, which uses `errors.As` to pick the status, and
  anything unrecognized becomes a 500.
- **Messages are dot-separated keys** (`user.create.password_required`) so
  clients can translate them. A 500 never exposes its wrapped cause in the body.
- **Input validation** goes through `api.DecodeAndValidate[T]`: strict JSON
  (unknown fields rejected, exactly one object) plus `validate` struct tags, and
  any failure returns a `ValidationError` with field details.
- **Canonical log line.** `HandleError` stores the error (for a 500, its
  unwrapped cause) in `RequestContextData`. The logger middleware writes it with
  the request log line, and the telemetry middleware records it on the span (see
  [ADR-004](ADR-004-logging-observability.md)).

Implementation details and examples are in [`docs/ERRORS.md`](../ERRORS.md).

## Consequences

**Positive**

- Services and controllers do not import `pgx`, and status codes are consistent
  across endpoints.
- Clients get a stable response shape (`error` key plus optional `details`).
- One log line per request carries both the status and the root cause.

**Negative**

- A new error category needs a new domain type and a branch in `HandleError`.
- Message keys are only as consistent as their authors. Nothing checks their
  naming or that a translation exists.
- Wrapping with `fmt.Errorf("%w")` still works with `errors.As`, but it is
  discouraged ("exact errors"), so context is sometimes only available in logs.
