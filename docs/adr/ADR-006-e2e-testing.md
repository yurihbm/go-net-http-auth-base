# ADR-006: End-to-End Testing Approach

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Unit tests mock the layers below them, and repository tests only exercise SQL.
Nothing proved that the real composition (global middleware chain, controllers,
services, repositories and PostgreSQL) works together, which is where bugs in
cookies, session rotation and authorization show up. Every service bootstrapped
from this template inherits the suite, so it must be fast, deterministic and
easy to extend.

## Decision

- **In-process, no mocks.** `factories.NewHandler(deps, cfg, tel)` builds the mux,
  registers every controller and applies the global middleware chain; both
  `cmd/main.go` and the E2E suite call it, so the tests run the production
  wiring. `internal/e2e` (`package e2e_test`, test files only) serves it with
  `httptest.NewServer` against the ephemeral PostgreSQL of `postgres.NewTestPool`.
  Running the compiled binary as a subprocess was rejected: it is slower, needs
  fragile readiness and port handling, and cannot collect coverage.
- **Lean scope: four flows.** Sign-up and login, session lifecycle (rotation and
  per-device logout), concurrent refresh, and authorization (user vs admin).
  Validation, 404/409 errors and rate limiting stay in unit tests, because
  repeating them over HTTP adds no signal.
- **Fixtures are Go helpers.** `seedUser` and `seedAdmin` run after the tables
  are truncated, and each test seeds only what it uses. They go through the real
  users repository with a bcrypt hash. SQL seed files were rejected: they pin a
  hash, bypass email normalization and break on schema changes. A production
  initial-admin bootstrap is out of scope.
- **Test environment.** `API_ENV=development` so cookies are not `Secure` over
  plain http, and high `RATE_LIMIT_*` values because every request shares the
  `127.0.0.1` bucket. Each simulated device is a client with its own cookie jar.
- **Composition tests that cannot fail cleanly over HTTP** live in
  `internal/repositories` next to `oauth_login_transaction_test.go`. Login
  transaction atomicity (`credentials_login_transaction_test.go`) forces a
  failure inside `startSession` and asserts nothing was persisted. Concurrent
  refresh is tested over HTTP.
- **Benchmarks and load testing (k6) are not part of the template.** There is no
  hot path besides bcrypt, which is slow on purpose. Benchmarks over mocks
  measure the mocks, and a performance baseline depends on the hardware and
  deployment of each derived application.

## Consequences

**Positive**

- A change to the middleware order, cookies, session handling or role checks
  fails a test that runs the same wiring as production.
- No mocks to keep in sync, and new flows only need a `seedX` helper and a
  `Test<Flow>` function.

**Negative / accepted residual risk**

- The suite needs Docker and is skipped with `go test -short`.
- Email verification is not covered: there is no seam to capture the verification
  link, and sending real mail costs money. Login does not require
  `email_verified`, so the flows do not depend on it.
- The rate limiter's `cleanupVisitors` goroutine has no stop signal, so each
  built handler leaks one goroutine. This is harmless in the suite, which builds
  one handler.
- Derived applications that need performance numbers must add their own
  benchmarks or load tests.
