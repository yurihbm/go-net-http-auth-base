# 📋 Project TODO

This file tracks the project features that should be implemented.

> **🧭 Current direction:** This project is a **generic, reusable backend
> template** for quickly bootstrapping any Go service. The immediate focus is
> **hardening the existing foundation** (consistency + correctness of what's
> already here) before layering observability on top. Concretely:
>
> 1. Fix the structural gaps first ([2.6 Architecture Hardening](#26-architecture-hardening)).
> 2. Then add telemetry/o11y the **lean** way — OpenTelemetry used directly in
>    infra/adapters, **no custom abstraction over OTel** ([2.7 Telemetry & Observability](#27-telemetry--observability-opentelemetry--grafana-lgtm)).

---

## 🎯 Quick Navigation

- [Phase 1: Quick Wins](#-phase-1-quick-wins)
- [Phase 2: Core Features](#-phase-2-core-features)
- [Phase 3: Polish & Documentation](#-phase-3-polish--documentation)

---

## 🚀 Phase 1: Quick Wins

High-impact, low-effort work that immediately improves the project.

### 1.1 OAuth User Info Providers

**Tasks**:

- [x] Add `OAuthProvider` interface to auth domain
  - [x] `GetAuthURL(state string) (string)`
  - [x] `GetUserInfo(code string) (*domain.OAuthProviderUserInfo, error)`
- [x] Create providers module: `internal/providers/oauth.go`
- [x] Implement GoogleOAuthProvider
- [x] Implement GitHubOAuthProvider
- [x] Implement MicrosoftOAuthProvider
- [x] Update AuthService to use providers
- [x] Update AuthController to use methods from AuthService
- [x] Update factories to inject OAuth providers
- [x] Add and update tests

### 1.2 Structured Logging with slog

**Tasks**:

- [x] Create `internal/logger/logger.go`
- [x] Replace `log.Println()` with `slog` calls in `cmd/main.go`
- [x] Update `postgres/connection.go` with structured logging
- [x] Create `internal/middlewares/logger_middleware`
- [x] Register the logger middlware at `cmd/main.go`
- [x] Setup JSON logging for production environment
- [x] Add context-aware logging (request IDs, user IDs)
- [x] Test logging output in local environment

**Files to modify**:

- `internal/logger/logger.go` (create)
- `internal/middlewares/logger_middleware.go` (create)
- `cmd/main.go`
- `postgres/connection.go`

---

### 1.3 Health Check Endpoints

**Tasks**:

- [x] Create `internal/controllers/health_controller.go`
- [x] Implement `GET /health` endpoint (basic liveness check)
- [x] Implement `GET /ready` endpoint (checks DB connectivity with timeout)
- [x] Register health endpoints in `cmd/main.go`
- [x] Add health controller tests in `internal/controllers/health_controller_test.go`
- [x] Test endpoints manually with curl

**Files to create/modify**:

- `internal/controllers/health_controller.go` (create)
- `internal/controllers/health_controller_test.go` (create)
- `cmd/main.go` (register routes)

---

### 1.4 GitHub Actions CI/CD

**Tasks**:

- [x] Create `.github/workflows/test.yml`
  - [x] Setup Go environment
  - [x] Add PostgreSQL service container
  - [x] Run tests with coverage
  - [x] Upload coverage reports
- [x] Create `.github/workflows/lint.yml`
  - [x] Setup golangci-lint
  - [x] Run linter on all code
  - [x] Fail on lint errors
- [x] Verify workflows trigger on push/PR
- [x] Add status badges to README.md

**Files to create**:

- `.github/workflows/test.yml` (create)
- `.github/workflows/lint.yml` (create)

---

### 1.5 Production Dockerfile

**Tasks**:

- [x] Create `docker/Dockerfile` with multi-stage build
- [x] Add builder stage (compile Go binary)
- [x] Add runtime stage (Alpine-based, minimal)
- [x] Setup non-root user for security (uid 1000)
- [x] Add HEALTHCHECK configuration
- [x] Test Docker build locally
- [x] Test Docker image runs correctly
- [x] Document Docker usage in README

**Files to create**:

- `docker/Dockerfile` (create)

---

### 1.6 Add License & CONTRIBUTING.md

**Tasks**:

- [x] Create `LICENSE` (MIT recommended)
- [x] Create `CONTRIBUTING.md` with:
  - [x] Code standards and conventions
  - [x] Commit message conventions
  - [x] Testing requirements (80%+ coverage)
  - [x] Pull request process
  - [x] Development setup instructions
- [x] Update README.md to link CONTRIBUTING.md
- [x] Verify LICENSE file is properly formatted

**Files to create**:

- `LICENSE` (create)
- `CONTRIBUTING.md` (create)

---

## ✅ Phase 1 Completion Checklist

- [x] Providers to fetch oauth user info are injected into AuthService
- [x] Tests run automatically on GitHub Actions
- [x] Docker image builds successfully
- [x] Logging appears in structured JSON format
- [x] Health endpoints (`/health`, `/ready`) return 200 OK
- [x] All Phase 1 code is tested

---

## 🔧 Phase 2: Core Features

Enterprise-grade error handling, security, and observability.

### 2.1 Custom Error Handling

**Tasks**:

- [x] Create `internal/domain/errors.go` with error types:
  - [x] `NotFoundError`
  - [x] `ValidationError`
  - [x] `ConflictError`
  - [x] `UnauthorizedError`
  - [x] `InternalServerError`
- [x] Implement error mapping in controllers to HTTP status codes
- [x] Add error details to JSON responses
- [x] Update service layer to return typed errors
- [x] Update repository layer to return typed errors
- [x] Add error handling tests
- [x] Document API errors
- [x] Refactor `InternalServerError` to support error wrapping (`Unwrap()`)
- [x] Update repositories to wrap original infrastructure errors
- [x] Implement centralized error logging by updating `LoggerMiddleware` to log errors setted on request context in `HandleError`

**Files to create/modify**:

- `internal/domain/errors.go` (create)
- `internal/controllers/*.go` (update error handling)
- `internal/services/*.go` (update error returns)
- `internal/repositories/*.go` (update error returns)

---

### 2.2 Request UUID Middleware

**Tasks**:

- [x] Create `internal/middlewares/request_uuid_middleware.go`
- [x] Generate unique request UUID for each request
- [x] Add request UUID to context
- [x] Include request UUID in all log messages
- [x] Include request UUID in response headers (`X-Request-UUID`)
- [x] Add middleware tests
- [x] Integrate middleware in `cmd/main.go`

**Files to create/modify**:

- `internal/middlewares/request_id_middleware.go` (create)
- `internal/middlewares/request_id_middleware_test.go` (create)
- `cmd/main.go` (register middleware)

---

### 2.3 Rate Limiting

**Tasks**:

- [x] Create `internal/middlewares/rate_limit_middleware.go`
- [x] Implement token bucket algorithm or sliding window
- [x] Rate limit per IP address
- [x] Return 429 (Too Many Requests) when limit exceeded
- [x] Add rate limit headers to responses:
  - [x] `X-RateLimit-Limit`
  - [x] `X-RateLimit-Remaining`
  - [x] `X-RateLimit-Reset`
- [x] Make rate limits configurable via environment variables
- [x] Add rate limiter tests
- [x] Integrate middleware in `cmd/main.go`

**Files to create/modify**:

- `internal/middlewares/rate_limit_middleware.go` (create)
- `internal/middlewares/rate_limit_middleware_test.go` (create)
- `cmd/main.go` (register middleware)
- `.env.example` (add rate limit config)

---

### 2.4 Audit Logging

**Tasks**:

- [x] Create database migration for audit logs table
- [x] Create `internal/domain/audit.go` with audit entry model
- [x] Create `internal/repositories/audit_repository.go`
- [x] Create `internal/services/audit_service.go`
- [x] Log sensitive operations (create user, update user, etc.)
- [x] Include user ID, action, timestamp, IP address in audit logs
- [x] Add audit log retrieval endpoint (admin only)
  - [x] Add admin role to user model
  - [x] Create a `role` middleware
  - [x] Create `internal/controllers/audit_controller.go`
  - [x] Implement `GET /audit-logs` endpoint with pagination and filtering
  - [x] Add middleware to protect the endpoint
- [x] Add comprehensive audit logging tests

**Files to create/modify**:

- `postgres/migrations/00XXX_add_audit_logs_table.up.sql` (create)
- `postgres/migrations/00XXX_add_audit_logs_table.down.sql` (create)
- `internal/domain/audit.go` (create)
- `internal/repositories/audit_repository.go` (create)
- `internal/services/audit_service.go` (create)
- `internal/controllers/audit_controller.go` (create)

---

### 2.5 Connection Pooling & Database Optimization

**Tasks**:

- [x] Review and optimize connection pool settings in `postgres/connection.go`
- [x] Set appropriate `MaxConns`, `MinConns`
- [x] Add connection pool health monitoring
- [x] Document connection pool configuration
- [x] Add tests for connection handling
- [x] Monitor slow queries

**Files to modify**:

- `postgres/connection.go`

---

### 2.6 Architecture Hardening

**Do this before telemetry.** These are consistency/correctness gaps in the
current foundation. In a _template_ they matter more than in a one-off app:
whoever bootstraps from it copies whichever pattern they land on first, so
inconsistency propagates.

#### 2.6.1 Uniform `context.Context` propagation (highest priority)

The `audit` domain propagates `context` correctly, but `users` and `auth` do
not — their interfaces take no context and the repositories use
`context.Background()` in ~9 places. This blocks cancellation, deadlines and any
future tracing. Make it context-everywhere, uniformly.

**Tasks**:

- [x] Add `context.Context` as the first argument to `UsersService` / `UsersRepository` methods (match `audit`)
- [x] Add `context.Context` to `AuthService` / `AuthRepository` methods
- [x] Thread `ctx` from controllers → services → repositories (use `r.Context()`)
- [x] Replace every `context.Background()` in `users`/`auth` repositories with the request `ctx`
- [x] Regenerate/update mocks for the new signatures
- [x] Update all affected tests

**Files to modify**:

- `internal/domain/{users,auth}.go`
- `internal/services/{users,auth}_service.go`
- `internal/repositories/{users,auth}_repository.go`
- `internal/controllers/{users,auth}_controller.go`
- `internal/mocks/*`

#### 2.6.2 Real input validation

Validation is currently **decorative**: `binding:"required"` is a Gin tag (this
project uses `net/http`) and `validate:"..."` targets go-playground/validator,
which is **not in `go.mod` and never invoked**. There is no validation layer.
The template must ship a real one (or be honest and drop the tags).

**Tasks**:

- [x] Decide approach: wire `go-playground/validator` at a single point, or remove dead tags
- [x] Remove unused Gin `binding:` tags from DTOs
- [x] Add a validator instance + one validation entry point (e.g. in `internal/api/request.go` decode helper)
- [x] Return `domain.ValidationError` with per-field `details` on failure
- [x] Add validation tests (success + per-field errors)

**Files to modify**:

- `internal/domain/*.go` (DTO tags)
- `internal/api/request.go`
- `internal/controllers/*.go`
- `go.mod`

#### 2.6.3 De-duplicate factory wiring

The `OAuthProviderRegistry` construction block (Google/GitHub/Microsoft) is
copy-pasted in `users_factory.go` and `auth_factory.go`.

**Tasks**:

- [ ] Extract OAuth registry construction into a shared factory/helper
- [ ] Reuse it in `users_factory` and `auth_factory`

**Files to modify**:

- `internal/factories/*.go`

#### 2.6.4 Minor cleanups

**Tasks**:

- [ ] Trim over-verbose godoc to match the project's "Zero Comments" convention (e.g. `internal/api/response.go`)
- [ ] Replace `// ==========` separators in `internal/domain/errors.go` (optional)

#### 2.6.5 Update `CLAUDE.md` to match the hardened conventions

`CLAUDE.md` still teaches the old patterns — most notably it prescribes
`context.Background()` in repositories. After the hardening above, the doc must
not keep teaching the patterns we just eliminated, or every future agent/dev
re-introduces them.

**Tasks**:

- [ ] Update the repository pattern to use propagated `context.Context` (drop the `context.Background()` example and the "should evolve to pass context" note) (after 2.6.1)
- [ ] Document the real validation approach (after 2.6.2)
- [ ] Document the shared OAuth registry factory (after 2.6.3)
- [ ] Add the dependency rule for telemetry: `otel` only in infra/adapters, never in `services`/`controllers` (after 2.7)

**Files to modify**:

- `CLAUDE.md`

#### 2.6.6 Fix current project TODOs

In-code `TODO` comments that represent real gaps in the template. Resolve them
(or consciously decide to keep + document why) so a bootstrap doesn't inherit
half-finished behavior.

**Tasks**:

- [ ] **OAuth callback is not transactional** — `internal/controllers/auth_controller.go:271,289`. In the "create user + link provider" path, if `AddUserOAuthProvider` fails the code manually deletes the just-created user. Wrap create+link in a single DB transaction to avoid orphaned records, then remove the manual rollback.
- [ ] **Rollback uses the cancelable request context** (Codex review, P2) — `internal/controllers/auth_controller.go:292`. Until the transaction above lands, the compensating `Delete` reuses `r.Context()`; if the request was canceled, the cleanup is canceled too and leaves an orphaned user. Use `context.WithoutCancel(r.Context())` (Go 1.21+) for the rollback. (Subsumed once the transaction is implemented.)
- [ ] **Invalid-JSON error handling is weak** — `internal/controllers/auth_controller.go:52` (and similar decode sites). Decode failures return a bare error string; return a `domain.ValidationError` with field details. Fold into the 2.6.2 validation entry point.
- [ ] **Role check hits the DB every request** — `internal/middlewares/role_middleware.go:25`. `RoleMiddleware` fetches the user from the database to read its role; carry the role in the JWT payload and read it from the token instead.
- [ ] **No authorization on user delete** — `internal/services/users_service.go:62`. `Delete` has no check for whether the caller is deleting itself or is an admin. Add the authorization rule.

**Files to modify**:

- `internal/controllers/auth_controller.go`
- `internal/middlewares/role_middleware.go`
- `internal/services/users_service.go`

---

### 2.7 Telemetry & Observability (OpenTelemetry + Grafana LGTM)

Distributed tracing, metrics and log correlation using OpenTelemetry and the
Grafana LGTM stack.

> **🪶 Lean approach (decided):** Use the **OpenTelemetry SDK directly** in
> infra/adapters. Do **not** wrap OTel in a custom `domain` abstraction — OTel is
> _already_ the vendor-neutral layer (no-op default, swappable exporters), and a
> hand-rolled wrapper duplicates it, is weakly typed, and grows to rival the
> business code. Vendor-neutrality of business code is preserved simply by
> keeping `otel` imports out of `services`/`controllers` (the few business
> metrics use the global meter or are recorded in middleware).
>
> The whole plan fits the task list below — no separate design doc needed.

**Tasks**:

- [ ] Single OTel SDK init (traces + metrics + logs exporters), gated by `OTEL_ENABLED`, with graceful shutdown — lives in one place (`internal/providers` or a small `internal/telemetry`)
- [ ] HTTP RED metrics + spans in a dedicated `TelemetryMiddleware` (otel directly)
- [ ] DB tracing + `db.query.duration` via a pgx `QueryTracer` (otel directly, co-located with `postgres`)
- [ ] Pool gauges + Go runtime metrics (`otel ... /instrumentation/runtime`)
- [ ] Log export to Loki: `slog` → `otelslog` bridge via a fan-out handler (keep stdout), automatic `trace_id` correlation
- [ ] Grafana LGTM in the **dev** compose + starter dashboards (API RED, Go runtime, Database)
- [ ] **Explicitly NOT building:** `domain.{TelemetryProvider,Tracer,Meter,Span,Counter,Histogram,Gauge}` interfaces, a NoOp provider, or telemetry mocks

---

## ✅ Phase 2 Completion Checklist

- [x] All errors return appropriate HTTP status codes
- [x] Rate limiter rejects requests after limit
- [x] Audit logs record sensitive operations
- [x] Request IDs appear in all logs
- [x] `context.Context` propagated uniformly across all layers (2.6.1)
- [x] Input validation is real and tested (2.6.2)
- [ ] Telemetry & observability operational (lean approach — see 2.7)
- [ ] Test coverage remains >85%
- [ ] All Phase 2 features are tested

---

## 📚 Phase 3: Polish & Documentation

Professional documentation and comprehensive testing.

### 3.1 API Documentation with Swagger/OpenAPI

**Tasks**:

- [ ] Install Swag: `go install github.com/swaggo/swag/cmd/swag@latest`
- [ ] Add doc comments to all handlers
- [ ] Generate Swagger spec: `swag init`
- [ ] Serve Swagger UI at `/swagger/index.html`
- [ ] Document all endpoints with:
  - [ ] Request parameters and body
  - [ ] Response schemas
  - [ ] Status codes and error messages
- [ ] Add Swagger configuration to `cmd/main.go`
- [ ] Test Swagger UI works

**Files to create/modify**:

- `cmd/main.go` (add Swagger handler)
- `internal/controllers/*.go` (add doc comments)
- `docs/swagger.json` (auto-generated)

---

### 3.2 Architecture Decision Records (ADRs)

**Tasks**:

- [ ] Create `docs/adr/` directory
- [ ] Write ADR-001: Layered Architecture Pattern
- [ ] Write ADR-002: Error Handling Strategy
- [ ] Write ADR-003: Database Strategy (PostgreSQL + sqlc)
- [ ] Write ADR-004: Logging & Observability
- [ ] Write ADR-005: Security Approach (CORS, rate limiting)
- [ ] Update README to link to ADRs

**Files to create**:

- `docs/adr/ADR-001-layered-architecture.md` (create)
- `docs/adr/ADR-002-error-handling.md` (create)
- `docs/adr/ADR-003-database-strategy.md` (create)
- `docs/adr/ADR-004-logging-observability.md` (create)
- `docs/adr/ADR-005-security-approach.md` (create)

---

### 3.3 End-to-End (E2E) Tests

**Tasks**:

- [ ] Create `internal/e2e/` directory
- [ ] Write E2E test for user creation flow
- [ ] Write E2E test for user authentication flow
- [ ] Write E2E test for error scenarios
- [ ] Write E2E test for rate limiting
- [ ] Setup test fixtures and database cleanup
- [ ] Document E2E testing approach

**Files to create**:

- `internal/e2e/e2e_test.go` (create)
- `internal/e2e/setup.go` (create)

---

### 3.4 Performance Benchmarks

**Tasks**:

- [ ] Add benchmark tests for controllers
- [ ] Add benchmark tests for services
- [ ] Add benchmark tests for repositories
- [ ] Document baseline performance
- [ ] Run benchmarks: `go test -bench=. ./...`
- [ ] Analyze and optimize hot paths

**Files to create**:

- `internal/controllers/*_benchmark_test.go` (create)
- `internal/services/*_benchmark_test.go` (create)

### 3.5 Load Testing

**Tasks**:

- [ ] Install k6: `go install github.com/grafana/k6@latest`
- [ ] Test user signup under load
- [ ] Test user login under load
- [ ] Test rate limiting behavior
- [ ] Ramp up from 10 to 100 concurrent users
- [ ] Create `test/load/spike_test.js` for spike testing:
  - [ ] Sudden spike to 500 concurrent users
  - [ ] Verify system recovery
- [ ] Document load testing setup and results
- [ ] Document baseline performance metrics
- [ ] Create GitHub Actions workflow for load testing (optional)

---

## ✅ Phase 3 Completion Checklist

- [ ] API documentation is complete and accurate
- [ ] ADRs explain key architectural decisions
- [ ] E2E tests cover critical user flows
- [ ] Benchmarks show performance characteristics
- [ ] Load tests run successfully and show performance metrics
