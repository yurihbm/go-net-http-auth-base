# ADR-003: Database Strategy (PostgreSQL + sqlc)

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

The template needs a relational store for users, OAuth links, sessions and audit
logs. It must support transactions across several repositories (login, OAuth
account resolution), enforce constraints such as unique emails in the database,
and keep queries type-safe without hiding SQL behind an ORM.

The alternatives considered were:

- an ORM (e.g. GORM), which is convenient but hides the SQL and relies on
  reflection and runtime errors;
- hand-written `database/sql`, which makes the SQL explicit but needs manual,
  error-prone scanning;
- **sqlc**, which keeps the SQL explicit and generates typed Go at build time.

## Decision

- **PostgreSQL 18** accessed through **`pgx/v5`** and a `pgxpool.Pool`. Pool
  size, lifetimes, health check period, connect timeout and the slow-query
  threshold come from validated environment variables (`config/config.go`).
- **sqlc** generates the `postgres` package from `postgres/queries/*.sql`
  against the migration schema (`make sqlc-gen`). Repositories wrap
  `postgres.Queries` and map rows to domain types (`toDomainUser`, ...).
- **golang-migrate** manages the schema (`make migrate-up` / `migrate-down`).
  While this is still a template, schema changes go into
  `000001_init_db.up.sql`/`.down.sql` instead of new migration files. New files
  start once the template is bootstrapped into a real service.
- **Transactions without leaking `pgx`.** Services depend on
  `domain.Transactor` and call `WithinTx(ctx, func(ctx) error)`.
  `PostgresTransactor` puts the `pgx.Tx` in the context, and repositories are
  built on `TxAwareDB`, which runs on that transaction when one is present and on
  the pool otherwise. A nested `WithinTx` joins the outer transaction.
- **Invariants live in the database:** a unique index on `lower(email)`,
  `ON DELETE CASCADE` from users to their sessions and OAuth links, and
  `audit_logs` partitioned by month (created at startup by
  `AuditLogsPartitionManager`, with a default partition as fallback).
- **Tests:** repository tests are integration tests against a real PostgreSQL
  in Docker. Every transactional flow has a test that forces a failure and
  asserts that nothing was persisted.

## Consequences

**Positive**

- Queries are plain SQL that can be reviewed and run in `psql`, and type errors
  show up at generation and compile time.
- Repositories join transactions automatically, so services stay unaware of
  `pgx`.
- Database constraints protect against race conditions that service-level checks
  alone would miss (e.g. duplicate emails).

**Negative**

- Every query change needs `make sqlc-gen`, and the generated code is committed.
- Dynamic queries (optional filters, sorting) are awkward in sqlc and need
  `sqlc.narg` tricks or several queries.
- The tied-to-context transaction is implicit: a closure that uses the outer
  `ctx` silently runs outside the transaction. The convention is to always name
  the closure parameter `ctx`.
- Folding changes into the initial migration only works while there is no
  production data. That rule has to be dropped when a real service is
  bootstrapped.
