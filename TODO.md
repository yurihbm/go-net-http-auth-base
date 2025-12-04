# 📋 Project TODO

This file tracks the project features that should be implemented.

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

- [ ] Create `internal/controllers/health_controller.go`
- [ ] Implement `GET /health` endpoint (basic liveness check)
- [ ] Implement `GET /ready` endpoint (checks DB connectivity with timeout)
- [ ] Register health endpoints in `cmd/main.go`
- [ ] Add health controller tests in `internal/controllers/health_controller_test.go`
- [ ] Test endpoints manually with curl

**Files to create/modify**:

- `internal/controllers/health_controller.go` (create)
- `internal/controllers/health_controller_test.go` (create)
- `cmd/main.go` (register routes)

---

### 1.4 GitHub Actions CI/CD

**Tasks**:

- [ ] Create `.github/workflows/test.yml`
  - [ ] Setup Go environment
  - [ ] Add PostgreSQL service container
  - [ ] Run tests with coverage
  - [ ] Upload coverage reports
- [ ] Create `.github/workflows/lint.yml`
  - [ ] Setup golangci-lint
  - [ ] Run linter on all code
  - [ ] Fail on lint errors
- [ ] Verify workflows trigger on push/PR
- [ ] Add status badges to README.md

**Files to create**:

- `.github/workflows/test.yml` (create)
- `.github/workflows/lint.yml` (create)

---

### 1.5 Production Dockerfile

**Tasks**:

- [ ] Create `Dockerfile` with multi-stage build
- [ ] Add builder stage (compile Go binary)
- [ ] Add runtime stage (Alpine-based, minimal)
- [ ] Setup non-root user for security (uid 1000)
- [ ] Add HEALTHCHECK configuration
- [ ] Test Docker build locally
- [ ] Test Docker image runs correctly
- [ ] Document Docker usage in README

**Files to create**:

- `Dockerfile` (create)

---

### 1.6 Add License & CONTRIBUTING.md

**Tasks**:

- [ ] Create `LICENSE` (MIT recommended)
- [ ] Create `CONTRIBUTING.md` with:
  - [ ] Code standards and conventions
  - [ ] Commit message conventions
  - [ ] Testing requirements (80%+ coverage)
  - [ ] Pull request process
  - [ ] Development setup instructions
- [ ] Update README.md to link CONTRIBUTING.md
- [ ] Verify LICENSE file is properly formatted

**Files to create**:

- `LICENSE` (create)
- `CONTRIBUTING.md` (create)

---

## ✅ Phase 1 Completion Checklist

- [ ] Providers to fetch oauth user info are injected into AuthService
- [ ] Tests run automatically on GitHub Actions
- [ ] Docker image builds successfully
- [ ] Logging appears in structured JSON format
- [ ] Health endpoints (`/health`, `/ready`) return 200 OK
- [ ] All Phase 1 code is tested

---

## 🔧 Phase 2: Core Features

Enterprise-grade error handling, security, and observability.

### 2.1 Custom Error Handling

**Tasks**:

- [ ] Create `internal/domain/errors.go` with error types:
  - [ ] `NotFoundError`
  - [ ] `ValidationError`
  - [ ] `ConflictError`
  - [ ] `UnauthorizedError`
  - [ ] `InternalServerError`
- [ ] Implement error mapping in controllers to HTTP status codes
- [ ] Add error details to JSON responses
- [ ] Update service layer to return typed errors
- [ ] Update repository layer to return typed errors
- [ ] Add error handling tests
- [ ] Document error codes in API docs

**Files to create/modify**:

- `internal/domain/errors.go` (create)
- `internal/controllers/*.go` (update error handling)
- `internal/services/*.go` (update error returns)
- `internal/repositories/*.go` (update error returns)

---

### 2.2 Request ID Middleware

**Tasks**:

- [ ] Create `internal/middlewares/request_id_middleware.go`
- [ ] Generate unique request ID for each request (UUID)
- [ ] Add request ID to context
- [ ] Include request ID in all log messages
- [ ] Include request ID in response headers (`X-Request-ID`)
- [ ] Add middleware tests
- [ ] Integrate middleware in `cmd/main.go`

**Files to create/modify**:

- `internal/middlewares/request_id_middleware.go` (create)
- `internal/middlewares/request_id_middleware_test.go` (create)
- `cmd/main.go` (register middleware)

---

### 2.3 Rate Limiting

**Tasks**:

- [ ] Create `internal/middlewares/rate_limiter.go`
- [ ] Implement token bucket algorithm or sliding window
- [ ] Rate limit per IP address
- [ ] Return 429 (Too Many Requests) when limit exceeded
- [ ] Add rate limit headers to responses:
  - [ ] `X-RateLimit-Limit`
  - [ ] `X-RateLimit-Remaining`
  - [ ] `X-RateLimit-Reset`
- [ ] Make rate limits configurable via environment variables
- [ ] Add rate limiter tests
- [ ] Integrate middleware in `cmd/main.go`

**Files to create/modify**:

- `internal/middlewares/rate_limiter.go` (create)
- `internal/middlewares/rate_limiter_test.go` (create)
- `cmd/main.go` (register middleware)
- `.env.example` (add rate limit config)

---

### 2.4 Audit Logging

**Tasks**:

- [ ] Create database migration for audit logs table
- [ ] Create `internal/domain/audit.go` with audit entry model
- [ ] Create `internal/repositories/audit_repository.go`
- [ ] Create `internal/services/audit_service.go`
- [ ] Log sensitive operations (create user, update user, etc.)
- [ ] Include user ID, action, timestamp, IP address in audit logs
- [ ] Add audit log retrieval endpoint (admin only)
- [ ] Add comprehensive audit logging tests

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

- [ ] Review and optimize connection pool settings in `postgres/connection.go`
- [ ] Set appropriate `MaxConns`, `MinConns`
- [ ] Add connection pool health monitoring
- [ ] Document connection pool configuration
- [ ] Add tests for connection handling
- [ ] Monitor slow queries

**Files to modify**:

- `postgres/connection.go`

---

## ✅ Phase 2 Completion Checklist

- [ ] All errors return appropriate HTTP status codes
- [ ] Rate limiter rejects requests after limit
- [ ] Audit logs record sensitive operations
- [ ] Request IDs appear in all logs
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
