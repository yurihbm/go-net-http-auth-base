# ADR-016: Cross-Layer Test Suites

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

ADR-006 put the HTTP end-to-end suite in `internal/e2e` and left the
"composition" tests, which run a service against several real repositories to
prove transaction atomicity, in `internal/repositories` as
`*_transaction_test.go`. Those files test service methods, so they sat loose
among the `<file>_test.go` repository tests and broke the `Test<Type>_<Method>`
naming (`TestPasswordReset_Transaction` names a flow, not a method). Coverage was
also measured per package, so the suites that exercise services and controllers
through the real wiring did not count toward them.

## Decision

- **Layout.** Cross-layer suites live under `internal/tests/`, test files only:
  - `internal/tests/e2e`: HTTP end-to-end flows over `factories.NewHandler` (the
    former `internal/e2e`, moved as is).
  - `internal/tests/integration`: service flows composed with several real
    repositories (transaction atomicity, failure injection). Each
    `<service>_service_test.go` mirrors the service file it covers and uses
    `Test<Type>_<Method>`; `integration_test.go` has `TestMain` and
    `truncateTables`, `helpers_test.go` the failing/blocking repository wrappers
    and count helpers.
- **Definitions.** Repository integration tests (one repository against SQL) stay
  next to the repository in `<file>_test.go`. A test that drives a service with
  real repositories goes to `internal/tests/integration`. A test that goes
  through HTTP goes to `internal/tests/e2e`.
- **Coverage.** `make test-cover` passes `-coverpkg` with the same package list it
  tests, so the e2e and integration suites count toward the packages they exercise.
- **Rejected.** Keeping the files in `internal/repositories` (naming and
  placement problem above); merging them into the repository test files (one
  repository file would test services and several repositories); putting them in
  `internal/services` (service tests there use mocks, and the package would need
  a database container).

## Consequences

- One extra container startup per full test run (the integration package has its
  own `TestMain`).
- `truncateTables` exists in three packages (repositories, integration, e2e) and
  must list every new table in each.
- With `-coverpkg`, the e2e and integration suites raise the reported coverage
  (94.8% to 95.6% when introduced), so the figure no longer measures unit tests
  alone.
- ADR-006 is unchanged except for its status note: its decision about where the
  suites live is superseded by this one.
