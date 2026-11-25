# ADR-006: End-to-End and Cross-Layer Test Suites

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Unit tests mock the layers below them, and repository tests only exercise SQL.
Nothing proved that the real composition (global middleware chain, controllers,
services, repositories and PostgreSQL) works together, which is where bugs in
cookies, session rotation and authorization show up. Every service bootstrapped
from this template inherits the suites, so they must be fast, deterministic and
easy to extend.

Some service flows also have to prove transaction atomicity by injecting a
failure between real repositories, which cannot fail cleanly over HTTP. Those
tests drive a service method with several real repositories, so they belong
neither among the `<file>_test.go` repository tests nor among the mocked service
tests, and they must still follow the `Test<Type>_<Method>` naming.

## Decision

- **In-process, no mocks.** `factories.NewHandler(ctx, deps, cfg, tel)` builds
  the mux, registers every controller and applies the global middleware chain;
  both `cmd/api` and the E2E suite call it, so the tests run the production
  wiring. The E2E suite serves it with `httptest.NewServer` against the
  ephemeral PostgreSQL of `postgres.NewTestPool`.
- **Layout.** Cross-layer suites live under `internal/tests/`, test files only:
  - `internal/tests/e2e` (`package e2e_test`): HTTP end-to-end flows over
    `factories.NewHandler`, named `Test<Flow>`.
  - `internal/tests/integration`: service flows composed with several real
    repositories (transaction atomicity, failure injection). Each
    `<service>_service_test.go` mirrors the service file it covers and uses
    `Test<Type>_<Method>`; `integration_test.go` has `TestMain` and
    `truncateTables`, `helpers_test.go` the failing/blocking repository wrappers
    and count helpers.
- **Definitions.** Repository integration tests (one repository against SQL)
  stay next to the repository in `<file>_test.go`. A test that drives a service
  with real repositories goes to `internal/tests/integration` (for example, login
  transaction atomicity forces a failure inside `startSession` and asserts
  nothing was persisted). A test that goes through HTTP goes to
  `internal/tests/e2e` (for example, concurrent refresh).
- **Lean E2E scope.** Sign-up by code and login, session lifecycle (rotation and
  per-device logout), concurrent refresh, authorization (user vs admin),
  step-up, the email change flow, logout-others, and password reset and change.
  Validation, 404/409 errors and rate limiting stay in unit tests, because
  repeating them over HTTP adds no signal.
- **Fixtures are Go helpers.** `seedUser` and `seedAdmin` run after the tables
  are truncated, and each test seeds only what it uses. They go through the real
  users repository with a bcrypt hash. A production initial-admin bootstrap is
  out of scope of the suite.
- **Email capture.** `factories.WithEmailProvider` injects a capturing provider,
  so the E2E flows read the codes and undo links that would be mailed.
- **Test environment.** `API_ENV=development` so cookies are not `Secure` over
  plain http, and high `RATE_LIMIT_*` values (global and credential) because
  every request shares the `127.0.0.1` bucket. Each simulated device is a client
  with its own cookie jar.
- **Coverage.** `make test-cover` passes `-coverpkg` with the same package list
  it tests, so the e2e and integration suites count toward the packages they
  exercise.
- **Benchmarks and load testing (k6) are not part of the template.** There is no
  hot path besides bcrypt, which is slow on purpose. Benchmarks over mocks
  measure the mocks, and a performance baseline depends on the hardware and
  deployment of each derived application.

## Alternatives considered

- **Running the compiled binary as a subprocess.** Slower, needs fragile
  readiness and port handling, and cannot collect coverage.
- **SQL seed files.** They pin a hash, bypass email normalization and break on
  schema changes.
- **Composition tests in `internal/repositories` as `*_transaction_test.go`.**
  They test service methods, so they sat loose among the repository tests and
  broke the `Test<Type>_<Method>` naming (`TestPasswordReset_Transaction` names a
  flow, not a method).
- **Merging them into the repository test files.** One repository file would
  test services and several repositories.
- **Putting them in `internal/services`.** Service tests there use mocks, and the
  package would need a database container.

## Consequences

**Positive**

- A change to the middleware order, cookies, session handling or role checks
  fails a test that runs the same wiring as production.
- No mocks to keep in sync, and new flows only need a `seedX` helper and a
  `Test<Flow>` function.
- Email flows are covered end to end without sending real mail.

**Negative / accepted residual risk**

- The suites need Docker and are skipped with `go test -short`.
- One extra container startup per full test run (the integration package has
  its own `TestMain`).
- `truncateTables` exists in three packages (repositories, integration, e2e) and
  must list every new table in each.
- With `-coverpkg`, the e2e and integration suites raise the reported coverage
  (94.8% to 95.6% when introduced), so the figure no longer measures unit tests
  alone.
- Derived applications that need performance numbers must add their own
  benchmarks or load tests.
