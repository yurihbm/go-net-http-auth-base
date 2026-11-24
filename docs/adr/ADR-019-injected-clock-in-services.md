# ADR-019: Injected Clock in Services

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Services called `time.Now()` directly (19 call sites) to compute expirations and
to decide whether a session, a step-up elevation or an email change lock was
still valid. Tests could only compare against the live clock with a tolerance
(`assert.WithinDuration(..., 5*time.Second)`), so the exact boundaries (a token
that expires at the current second, a session that ends one second from now)
could not be asserted. The rate limit middleware already takes a
`now func() time.Time`.

## Decision

- Services never call `time.Now()`. Every service that needs the time takes a
  `now func() time.Time` as the **last constructor parameter** (`TokenService`,
  `UserService`, `EmailChangeService`, `PendingSignupService`, `PasswordService`,
  `AuthService`, `StepUpService`) and calls `s.now()`. Helpers that need the
  time receive the value as a parameter.
- `factories.NewDependencies` passes `time.Now`; there is a single production
  clock.
- `TokenService` also validates the `exp` claim with the same clock
  (`jwt.WithTimeFunc(s.now)`), so generation and verification agree.
- Unit tests pass a fixed clock (`testNow`/`testClock` in
  `internal/services/clock_test.go`), assert timestamps with exact equality and
  cover the boundaries (at the instant, one second before). A test that needs to
  move time uses a variable the closure reads.
- Out of scope: the `now()` evaluated by PostgreSQL inside SQL queries (code and
  session TTL checks done in a query, `ON CONFLICT` windows). It stays
  database-side, is covered by the repository and integration tests, and those
  tests keep using the real clock.

## Consequences

- Expiry and TTL logic written in Go is tested without tolerance and without
  sleeping.
- Every constructor of a service that reads the time gains a parameter; new
  services follow the same shape.
- Go and SQL decide on different clocks; both read the same host in practice,
  and the SQL comparisons are not testable with a fixed clock.
