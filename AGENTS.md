# AI Agent Context

Go REST API for user authentication and user management, on PostgreSQL, with a layered architecture (controllers, services, repositories, domain). This file holds what applies to every task; area-specific conventions live in path-scoped rules under `.claude/rules/` (loaded when matching files are read or edited) and in `docs/`.

## Technologies

Go with standard `net/http` (Go 1.22+ method patterns), PostgreSQL, `golang-migrate` (migrations), `sqlc` (type-safe queries), `go-playground/validator`, testify, testcontainers, swaggo/swag, OpenTelemetry, `air` (live reload), Go Modules.

## Layout

- `cmd/api/`: the server; builds config, telemetry, the pool and `factories.NewHandler`, then serves.
- `cmd/promote-admin/`: one-shot CLI (`promote-admin <email>`) that promotes an existing user to admin.
- `config/`: loads and validates every environment variable (`config.Load`) and builds the OAuth client configs.
- `internal/api/`: JSON decoding/validation, response format, error mapping, cookies.
- `internal/controllers/`: HTTP handlers, calling one service method each.
- `internal/services/`: business logic.
- `internal/repositories/`: data access on `sqlc` queries.
- `internal/providers/`: adapters for external services (OAuth providers, email).
- `internal/middlewares/`: auth, step-up, role, CORS, rate limit, logger, telemetry, request UUID, request context data.
- `internal/domain/`: entities, DTOs, errors and every service/repository interface.
- `internal/factories/`: composition root. `dependencies.go` (`NewDependencies`) builds the shared graph once; thin per-controller factories wire it into controllers; `handler.go` (`NewHandler`) builds the mux, registers every controller and applies the global middleware chain (used by `cmd/api` and the E2E suite, so tests run the production wiring).
- `internal/mocks/`: testify mocks of the domain interfaces.
- `internal/tests/`: cross-layer test suites (test files only): `e2e/` (HTTP flows over `factories.NewHandler`) and `integration/` (service flows composed with real repositories).
- `internal/infra/`: background tasks (`AuditLogsPartitionManager`, `ExpiredRecordsSweeper`).
- `internal/logger/`, `internal/telemetry/`: `slog` setup and the OpenTelemetry SDK bootstrap.
- `internal/shared/`: request context data (`RequestContextData`) shared by middlewares, `api` and controllers.
- `internal/env/`: typed environment variable lookups used by `config`.
- `postgres/`: connection, migrations, `queries/` and generated `sqlc` code, query tracers, pool metrics, the integration test helper (`NewTestPool`).
- `docker/`: Dockerfile, dev compose (PostgreSQL, pgAdmin, Grafana LGTM), prod compose, Grafana dashboards.
- `docs/`: ADRs (`adr/`), generated Swagger spec (`swagger/`), `AUTH.md`, `ERRORS.md`, `AUDIT.md`.

## Skills

Prefer these project skills (`.claude/skills/`) over writing the boilerplate by hand:

- `go-resource-scaffolder`: scaffolds a vertical slice (domain, repository with integration tests, service and controller with unit tests, mocks, factory): `npx tsx .claude/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName> [--singular]` (e.g. `Product` creates `products_controller.go`, `Auth --singular` creates `auth_controller.go`). Then follow the printed next steps (wire the service in `dependencies.go`, register the factory in `internal/factories/handler.go`, add the table and queries, implement the repository placeholders).
- `go-migration-scaffolder`: schema and query workflow (`npx tsx .claude/skills/go-migration-scaffolder/scripts/create-migration.ts <migration_name>`). During the template phase do not run its script (see below).

## Commands

```bash
make setup                 # install the required tools (air, migrate, sqlc, swag) and tidy
air                        # run with live reload
make build                 # production binary in bin/
docker compose --env-file .env -f docker/docker-compose.dev.yaml up -d   # dev PostgreSQL, pgAdmin, Grafana
make migrate-up            # apply pending migrations
make migrate-down          # revert the last migration
make migrate-create name=<migration_name>   # new migration (not during the template phase)
make sqlc-gen              # regenerate Go code from postgres/queries/*.sql
make swagger-gen           # regenerate docs/swagger/ from the handler annotations
go test -short ./...       # unit tests (skips integration tests)
go test ./...              # everything (integration and E2E tests need Docker)
make test-e2e              # E2E suite only
make show-cover            # coverage as reported by CI
make check                 # build, vet, lint, full tests and swagger/sqlc drift (needs Docker)
```

## Rules That Always Apply

### Workflow

- **TDD**: new logic, bug fixes and features start with a failing test; refactors keep the existing tests green and add missing coverage. Tests live next to the code they test (`_test.go`).
- **Test Naming**: one `Test<Type>_<Method>` per tested method (`TestNew<Type>` for constructors), scenarios as `t.Run` subtests (`"success"`, `"error - <description>"`); never a standalone `Test...` per scenario. E2E flows are the exception (`Test<Flow>`). Details in `.claude/rules/testing.md`.
- **Template Phase**: while this repository is a template, schema changes go into `postgres/migrations/000001_init_db.up.sql`/`.down.sql`, never a new migration file. Re-apply with `make migrate-down && make migrate-up`, then `make sqlc-gen`.
- **Before a PR**: run `make check`; it runs what the required CI checks run (build, vet, lint, full tests, swagger and sqlc drift).
- **Swagger**: every handler carries swag annotations. Run `make swagger-gen` after changing a handler or a DTO it uses and commit `docs/swagger/`; CI fails on drift.

### Code

- **Layers**: controllers decode, validate and call services; services hold business rules; repositories only persist. Program to the interfaces in `internal/domain`, so everything can be mocked.
- **Dependency Injection**: every dependency comes through a constructor, never created inside the dependent struct. Shared instances are built once in `internal/factories/dependencies.go`, not per factory. Services get the clock as `now func() time.Time` and never call `time.Now()` (ADR-016).
- **Transactions**: in `WithinTx(ctx, func(ctx context.Context) error { ... })` always name the closure parameter `ctx` so it shadows the outer one; the outer context silently runs queries outside the transaction.
- **IDs**: always UUIDv7. Tables use a `uuid uuid DEFAULT uuidv7()` primary key; IDs generated in Go (persisted rows, request UUIDs) use `uuid.NewV7()`.
- **Errors**: dot-separated keys (e.g., `"users.email.conflict"`) for i18n, documented in `docs/ERRORS.md`. Return errors as-is unless wrapping adds real context.
- **Pointers**: services and repositories take DTOs and entities by value and return pointers (`*domain.User`), so a `nil` result pairs with an error.
- **Comments**: code is self-documenting. Comments only for swag annotations on handlers (and the general API info above `main` in `cmd/api/main.go`) and for explaining complex business logic. No decorative godoc.
- **Telemetry Imports**: `go.opentelemetry.io/otel*` may only be imported in `internal/telemetry`, `internal/middlewares`, `internal/logger`, `internal/factories`, `postgres` and `cmd`; never in `services`, `controllers`, `domain` or `repositories`.
- **Logging**: use `slog.*Context(ctx, ...)` in request paths so logs carry the trace.
- **Formatting**: standard Go formatting (`gofmt`), `golangci-lint` in CI.

### Architecture Decision Records

Decisions live in `docs/adr/` (index and rules in `docs/adr/README.md`). Write an ADR in the same PR as the feature when a decision:

- changes or adds a convention described in this file or in `.claude/rules/` (layers, errors, transactions, telemetry, testing);
- adds or replaces an infrastructure dependency (database, queue, external provider, core library);
- changes the security model (tokens, sessions, authorization) or accepts a residual risk;
- is hard to reverse, or real alternatives were weighed.

Local choices (naming, a new helper, a refactor that keeps behavior) do not need one. When in doubt, ask the user.

- **Format**: Nygard (Status, Date, Context, Decision, Consequences), in English, as `docs/adr/ADR-00N-short-title.md` with the next number, added to the index table.
- **Immutability**: while this repository is a template, edit the affected ADRs so the set describes the final state (every ADR `Accepted`, no superseded records), so derived projects start from the final decisions. After the template phase, never rewrite the decision of an accepted ADR: write a new ADR and set the old one's status to `Superseded by ADR-00N`.
- **Diagrams (optional)**: only when a structure or flow is hard to explain in text. The existing ones were made with [Archify](https://github.com/tt-a1i/archify). Commit only the JSON source and the SVG export to `docs/adr/diagrams/`. If Archify is unavailable, ship the ADR without the diagram.
- **Keep docs in sync**: if the ADR changes a convention, update the matching section of this file, the rule in `.claude/rules/` or `docs/AUTH.md` in the same PR.

## Where to Read More

| Topic | File | Loaded for |
| --- | --- | --- |
| Controllers, `api`, Swagger UI | `.claude/rules/controllers.md` | `internal/controllers/**`, `internal/api/**` |
| Services | `.claude/rules/services.md` | `internal/services/**` |
| Repositories, transactions, `sqlc`, schema | `.claude/rules/repositories.md` | `internal/repositories/**`, `postgres/**` |
| Domain models, DTOs, enums | `.claude/rules/domain.md` | `internal/domain/**` |
| Tests, mocks, E2E | `.claude/rules/testing.md` | `**/*_test.go`, `internal/mocks/**`, `internal/tests/**` |
| Telemetry, logging, dashboards | `.claude/rules/telemetry.md` | telemetry, middlewares, logger, tracers, Grafana, `cmd/**` |
| Auth and email invariants | `.claude/rules/auth.md` | auth, users, sessions, step-up, sign-up and email files |
| Sign-up, OAuth, sessions, step-up, email change | `docs/AUTH.md` | read on demand |
| Error keys and mapping | `docs/ERRORS.md` | read on demand |
| Audit log actions | `docs/AUDIT.md` | read on demand |
| Decisions | `docs/adr/README.md` | read on demand |
