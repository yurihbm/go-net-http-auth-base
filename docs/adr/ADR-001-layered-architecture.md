# ADR-001: Layered Architecture Pattern

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

This project is a reusable template for bootstrapping Go backend services. Each
service built from it adds its own resources on top of users and authentication,
so the structure must:

- make it obvious where new code goes, so every resource looks the same;
- keep business rules testable without HTTP or a database;
- allow infrastructure (database, OAuth providers, email) to be swapped or
  mocked without touching business logic;
- stay close to the standard library (`net/http`), with no web framework or DI
  container to learn.

## Decision

Use a three-layer architecture with a shared `domain` package and a single
composition root.

![Layered architecture and composition root](diagrams/layered-architecture.svg)

<sub>[Diagram source](diagrams/layered-architecture.json) ([made with Archify](README.md#diagrams))</sub>

- **Controllers** (`internal/controllers`) handle HTTP: decode and validate
  input with `api.DecodeAndValidate`, call exactly one service method, and write
  the response or map the error with `api.HandleError`. They implement
  `Controller` (`RegisterRoutes(*http.ServeMux)`) and use Go 1.22+ method
  patterns (`POST /users`, `GET /users/{uuid}`).
- **Services** (`internal/services`) hold the business rules. Structs are
  unexported and the constructors return domain interfaces. Flows that span
  several steps (e.g. `AuthService.OAuthLogin`) are a single service method, so
  controllers stay thin.
- **Repositories** (`internal/repositories`) own persistence through
  sqlc-generated queries (see [ADR-003](ADR-003-database-strategy.md)).
  **Providers** (`internal/providers`) are the equivalent adapters for external
  APIs (OAuth, email).
- **Domain** (`internal/domain`) defines entities, DTOs, errors and every
  service, repository and provider interface. Each layer depends only on the
  interfaces of the layer below.
- **Composition root.** `factories.NewDependencies` builds repositories, services
  and shared middlewares once. `factories.NewHandler` (called by `cmd/api`)
  passes `*Dependencies` to thin per-controller factories and wraps the mux in
  the global middleware chain. No struct creates its own dependencies.
- `context.Context` is the first argument of every service and repository method
  and flows from `r.Context()` down to the database.

## Consequences

**Positive**

- Each layer is unit-tested against mocks of the layer below
  (`internal/mocks`). Only repositories need a real database.
- Adding a resource is mechanical, and the `go-resource-scaffolder` skill
  generates the whole vertical slice.
- Swapping an adapter (e.g. `LogEmailProvider` vs `ResendEmailProvider`) is a
  one-line change in the composition root.

**Negative**

- More files and boilerplate per resource than a framework-based approach:
  interface, implementation, mock and factory for every service and repository.
- Mocks must be kept in sync with the interfaces by hand.
- Cross-cutting rules (authorization, transactions, normalization) are
  conventions that reviewers have to enforce. For example, a transaction closure
  must use its own `ctx`, or the query runs outside the transaction.
