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

#### 2.6.3 Composition root & DI hygiene (architecture review)

Each controller factory currently rebuilds the whole dependency graph:
`UsersFactory` and `AuthFactory` each construct their own `UsersRepository`,
`AuthRepository`, OAuth provider registry, and `AuditService` — 3-4 instances
of everything per process, and no single place where the app's dependencies
exist. This covers (and replaces) the earlier "de-duplicate the OAuth registry
block" task: with a composition root there is nothing left to duplicate.

**Tasks**:

- [x] Build shared dependencies once in `cmd/main.go` (repositories, services, OAuth registry, middlewares) and pass them into thin per-controller factories — or drop the factories entirely
- [x] Factories/constructors return errors to `main` instead of `panic` (e.g. OAuth registry construction in `users_factory.go:34`)

**Files to modify**:

- `cmd/main.go`
- `internal/factories/*.go`

#### 2.6.4 Minor cleanups

**Tasks**:

- [x] Trim over-verbose godoc to match the project's "Zero Comments" convention (e.g. `internal/api/response.go`)
- [x] Replace `// ==========` separators in `internal/domain/errors.go` (optional)
- [x] **Non-deterministic error mapping precedence** (architecture review) — `internal/api/errors.go:35-62`. `HandleError` runs five sequential `errors.As` blocks, so a wrapped chain matching two types silently takes the *last* match. Use `switch`/`else if` for deterministic precedence.
- [x] **Two sources of truth for the authenticated user UUID** (architecture review) — `internal/middlewares/auth_middleware.go:51-58`. `AuthMiddleware` writes the UUID both to the `UserUUIDKey` context value and to `RequestContextData.UserUUID`. Pick one and migrate readers.

#### 2.6.5 Update `CLAUDE.md` to match the hardened conventions

`CLAUDE.md` still teaches the old patterns — most notably it prescribes
`context.Background()` in repositories. After the hardening above, the doc must
not keep teaching the patterns we just eliminated, or every future agent/dev
re-introduces them.

**Tasks**:

- [ ] Update the repository pattern to use propagated `context.Context` (drop the `context.Background()` example and the "should evolve to pass context" note) (after 2.6.1)
- [ ] Document the real validation approach (after 2.6.2)
- [ ] Document the composition-root wiring (after 2.6.3)
- [ ] Document the `OAuthLogin` service pattern — controllers stay thin (after 2.6.9)
- [ ] Add the dependency rule for telemetry: `otel` only in infra/adapters, never in `services`/`controllers` (after 2.7)

**Files to modify**:

- `CLAUDE.md`

#### 2.6.6 Fix current project TODOs

In-code `TODO` comments that represent real gaps in the template. Resolve them
(or consciously decide to keep + document why) so a bootstrap doesn't inherit
half-finished behavior.

**Tasks**:

> **Note:** the fixes *inside* the OAuth callback flow (missing transaction,
> cancelable rollback context, swallowed lookup errors, state↔provider
> binding) moved to [2.6.9](#269-extract-oauth-login-business-logic-into-the-service-layer)
> — they get fixed once, in the logic's final home, as part of the extraction.

- [ ] **Invalid-JSON error handling is weak** — `internal/controllers/auth_controller.go:52` (and similar decode sites). Decode failures return a bare error string; return a `domain.ValidationError` with field details. Fold into the 2.6.2 validation entry point.
- [ ] **Role check hits the DB every request** — `internal/middlewares/role_middleware.go:25`. `RoleMiddleware` fetches the user from the database to read its role; carry the role in the JWT payload and read it from the token instead.
- [ ] **No self-or-admin authorization on user read/update/delete** (security review, high) — `internal/controllers/users_controller.go:34-36`, `internal/services/users_service.go:50,66`. Any authenticated user can `GET`, `PUT`, or `DELETE` `/users/{uuid}` for **any** user. Update is takeover-class: change a victim's email to one the attacker controls at an OAuth provider, then OAuth-login — the attacker's provider account gets linked to the victim's user. Read is an IDOR leaking name/email/role (password hash is already excluded via `json:"-"`). Add one self-or-admin rule covering all three endpoints.
- [ ] **OAuth flow has no browser-session binding (login CSRF) and no PKCE** (security review, medium-high) — `internal/controllers/auth_controller.go:125,155`. The state JWT proves the server minted it but nothing ties it to the browser that started the flow: an attacker can start the flow themselves, take the resulting callback URL (valid state + their code), and make a victim's browser visit it — silently logging the victim into the attacker's account. The open-redirect fix does not cover this. Set a random nonce in a short-lived cookie at login, embed it in the state payload, compare on callback. Also add PKCE via `oauth2.S256ChallengeOption`.
- [ ] **Rate limiter keys on `r.RemoteAddr` including the port** (security review) — `internal/middlewares/rate_limit_middleware.go:38`. The raw `ip:port` string means every new TCP connection gets a fresh bucket, defeating per-IP limiting (and behind a proxy it keys on the proxy anyway). Use `net.SplitHostPort` and decide on a trusted-proxy header policy.
- [ ] **No per-account login throttling + timing-based user enumeration** (security review) — `internal/services/auth_service.go:37-49`. Only the (currently broken) global IP limiter protects `/auth/login` from password guessing; add per-account throttling or lockout. Also `bcrypt.CompareHashAndPassword` only runs when the email exists — compare against a dummy hash on the miss path to equalize timing.
- [ ] **Refresh cookie scoped to `/`** (security review) — `internal/controllers/auth_controller.go:355`. The refresh token is sent on every request instead of only the refresh endpoint. Set `Path: "/auth/refresh"`.
- [ ] **CORS middleware nits** (security review) — `internal/middlewares/cors_middleware.go:44,69,73`. `Vary: Origin` is only set when the origin is allowed (shared-cache poisoning for the disallowed case — set it unconditionally); preflights return 200 even for disallowed origins; and the handler mutates `m.maxAge` per request — a data race under concurrency (resolve the default in the constructor instead).
- [ ] **Open redirect via unvalidated `redirect_uri`** (security review) — `internal/controllers/auth_controller.go:137,339`. `redirect_uri` is read raw from the query string on `LoginWithOAuthProvider`, signed into the OAuth state token unchecked, and passed straight to `http.Redirect` at the end of `OAuthProviderCallback`. Signing doesn't help — an attacker gets a legitimately-signed state for any URL just by using the normal login link with their own `redirect_uri`. Add an `OAUTH_CALLBACK_ALLOW_LIST` env var (CSV of exact allowed redirect URIs) and validate against it at login time (before minting the state token), failing closed if unset/empty.
- [ ] **Unset `JWT_SECRET` silently signs with an empty key** (security review, critical) — `internal/services/auth_service.go:78,143`. Both `GenerateToken` and `VerifyToken` call `os.Getenv(JWT_SECRET_KEY)` with no validation; if the var is unset, HMAC-SHA256 signs/verifies with `[]byte("")` — a known key, letting anyone forge a valid access token for any user. Fail fast at startup (refuse to boot) if `JWT_SECRET` is empty or below a minimum length. Fold into 2.6.7's centralized config validation.
- [ ] **Unchecked claim type assertions in `VerifyToken` panic on malformed tokens** — `internal/services/auth_service.go:86-88`. `claims["sub"].(string)`, `claims["aud"].(string)`, `int64(claims["exp"].(float64))` run before the `ok`/`token.Valid` check on line 90; a token with a missing/wrong-typed claim panics instead of returning an error — a DoS surface since this path is reachable via attacker-controlled OAuth state and refresh tokens. Use two-value assertions (`v, ok := claims["sub"].(string)`) and return `ErrInvalidToken` on failure.
- [ ] **GitHub `EmailVerified` is hardcoded `true`** (security review) — `internal/providers/github_oauth_provider.go:76`. Sourced from `GET /user`, whose public `email` field isn't attested as verified by GitHub. The controller's Case-2 account-linking logic relies on `EmailVerified` specifically to prevent account-takeover-by-email-match — for GitHub that gate is currently a no-op. Call `GET /user/emails` instead and check the `verified`+`primary` flags for the matching address.
- [ ] **OAuth token exchange has no timeout** — `internal/providers/{google,github,microsoft}_oauth_provider.go:36`. `p.config.Exchange(ctx, code)` falls back to `http.DefaultClient` (no timeout) unless the context carries `oauth2.HTTPClient`, unlike the userinfo fetch which already sets one. A slow/unresponsive provider token endpoint can hang the request indefinitely. Set an `oauth2.HTTPClient` with a timeout (e.g. 10s, matching the userinfo client) on the context passed to `Exchange`.

**Files to modify**:

- `internal/controllers/auth_controller.go`
- `internal/controllers/users_controller.go`
- `internal/middlewares/role_middleware.go`
- `internal/middlewares/rate_limit_middleware.go`
- `internal/middlewares/cors_middleware.go`
- `internal/services/users_service.go`
- `internal/services/auth_service.go`
- `internal/providers/github_oauth_provider.go`
- `internal/providers/{google,github,microsoft}_oauth_provider.go`
- `.env.example`

#### 2.6.7 Centralized environment configuration

Env var reading is currently scattered `os.Getenv` calls across the codebase
(`auth_controller.go`'s `setAuthCookies`, `auth_service.go`'s JWT secret,
`config/oauth.go`, `cors_factory.go`'s `parseAllowedOrigins`, the rate-limit
factory, etc.), each with its own ad-hoc parsing and no shared validation. In a
*template* this means every bootstrap re-invents (or forgets) validation.

**Tasks**:

- [ ] Create `internal/config/config.go` with a `Config` struct covering all env vars (JWT secret, CORS origins, rate limits, OAuth client IDs/secrets, `API_ENV`, DB connection, etc.)
- [ ] Implement a single `Load()` that parses (CSV lists, durations, bools) and validates (fail-fast) at startup — refuse to boot on missing/invalid required values (e.g. empty `JWT_SECRET`)
- [ ] Call `config.Load()` once in `cmd/main.go` and inject the relevant sub-config into each factory instead of `os.Getenv` calls
- [ ] Remove scattered `os.Getenv` calls from `auth_controller.go`, `auth_service.go`, `config/oauth.go`, `cors_factory.go`, rate-limit factory
- [ ] Add config validation tests (missing/invalid env vars fail fast with a clear error)

**Files to modify**:

- `internal/config/config.go` (create)
- `cmd/main.go`
- `internal/controllers/auth_controller.go`
- `internal/services/auth_service.go`
- `internal/config/oauth.go`
- `internal/factories/cors_factory.go`
- `internal/factories/*.go` (rate limit and others reading env vars)

#### 2.6.8 Refresh token revocation

Refresh tokens are pure stateless JWTs today — `RefreshToken()`
(`internal/services/auth_service.go:102`) issues a new pair on rotation but
never invalidates the old one, and `Logout` only clears cookies client-side.
A stolen refresh token remains valid for the full 7-day
`TokenExpirationRefresh` window with no server-side revocation path.

Not strictly mandatory (many APIs accept this residual risk with short-lived
access tokens), but worth closing given the long refresh window already
exists. Default to the cheaper option: track a single active refresh token
`jti` per user rather than a growing revocation table — simpler, no
unbounded storage, at the cost of only one active session per user. A full
revocation store (dedicated table, checked on every refresh) is the upgrade
path if/when multi-device sessions are needed.

**Tasks**:

- [ ] Decide: single-`jti`-per-user (default) vs. full revocation table (if multi-device sessions matter)
- [ ] Add `current_refresh_jti` (or similar) column to the `users` table directly in `postgres/migrations/000001_init_db.up.sql`/`.down.sql` — this is still template setup, not a real app in production, so fold it into the initial migration rather than adding a new one (new migration files are for once the template is bootstrapped into a real app)
- [ ] Include a `jti` claim when generating refresh tokens (`GenerateToken`)
- [ ] On `RefreshToken()`, verify the presented `jti` matches the stored one before issuing a new pair; overwrite on rotation
- [ ] On `Logout`, clear the stored `jti` server-side (not just client-side cookies)
- [ ] **Re-check the user on refresh** (security review) — `RefreshToken()` issues a new pair from the token subject alone; a deleted user keeps working tokens for the full refresh window. Verify the user still exists before issuing new tokens. (Comes for free with the `jti` lookup above.)
- [ ] **Cap the total session lifetime** (security review) — every refresh issues a fresh 7-day refresh token, so a stolen token can be renewed forever. Carry an `auth_time` (original login timestamp) claim through rotations and reject refresh once an absolute maximum session age is exceeded.
- [ ] Add tests: reused/stale refresh token is rejected after rotation; logout invalidates the refresh token server-side; refresh fails for a deleted user; refresh fails past the absolute session lifetime

**Files to modify**:

- `postgres/migrations/000001_init_db.up.sql`
- `postgres/migrations/000001_init_db.down.sql`
- `internal/services/auth_service.go`
- `internal/controllers/auth_controller.go`
- `internal/domain/{auth,users}.go`
- `internal/repositories/{auth,users}_repository.go`

#### 2.6.9 Extract OAuth login business logic into the service layer

**Architecture review — do this BEFORE the remaining OAuth callback fixes in
2.6.6**, so the logic is fixed once in its final home instead of twice.

`OAuthProviderCallback` (`internal/controllers/auth_controller.go:155-340`) is
~185 lines of authentication business logic living in the controller: the
three account-resolution cases, the email-verification takeover gate,
create+link orchestration with manual rollback, and token minting. That's why
the controller needs `usersService` injected, why the transaction fix is
awkward (controllers can't own DB transactions cleanly), and why this logic is
only testable through HTTP-shaped tests. Extract a single
`AuthService.OAuthLogin(ctx, provider, code, state) (AuthTokens, error)` and
leave the controller with decode → call → set cookies → redirect.

The following previously-separate fixes are **folded in here** (moved from
2.6.6):

- [ ] **OAuth callback is not transactional** — in the "create user + link provider" path, if `AddUserOAuthProvider` fails the code manually deletes the just-created user (`auth_controller.go:277-301`), and that compensating `Delete` reuses the cancelable `r.Context()` — a canceled request leaves an orphaned user. Wrap create+link in a single DB transaction inside `OAuthLogin`; the manual rollback (and its context problem) disappears.
- [ ] **Lookup errors silently swallowed** — `GetUserOAuthProvider` and `GetByEmail` errors are discarded (`_`) at `auth_controller.go:232,248`; a transient DB failure falls through into account-creation/linking instead of surfacing a 500. Branch on `domain.NotFoundError` explicitly and return anything else as an error.
- [ ] **State token not bound to the path's provider** — the state JWT's `Subject` is the provider name at login, but nothing compares it to the callback's provider (`VerifyToken` checks only signature/expiry/audience), so a `google` state is accepted on `/auth/github/callback`. Compare `Subject` to the provider inside `OAuthLogin` and reject on mismatch.

**Tasks**:

- [ ] Add `OAuthLogin` to `domain.AuthService`; move Cases 1/2/3 and the email-verified gate into `services/auth_service.go`
- [ ] Add transaction support to the repository layer for the create+link path (fixes the transactional item above)
- [ ] Fix the swallowed-lookup and state↔provider checks as part of the move
- [ ] Slim `OAuthProviderCallback` to decode/validate → `OAuthLogin` → cookies → redirect; drop `usersService` from `AuthController` if no longer needed
- [ ] Restructure tests: business cases become service unit tests; the controller test covers only HTTP concerns

**Files to modify**:

- `internal/domain/auth.go`
- `internal/services/auth_service.go`
- `internal/controllers/auth_controller.go`
- `internal/repositories/auth_repository.go`
- `internal/mocks/*`

#### 2.6.10 Narrow token interfaces (ISP)

`domain.AuthService` has 10 methods. `AuthMiddleware` depends on the whole
interface but calls only `VerifyToken`; `GenerateToken` is only public on the
interface because the controller currently mints tokens itself (resolved by
2.6.9). `RoleMiddleware` similarly takes the full `UsersService` for one
`GetByUUID` — which the role-in-JWT fix in 2.6.6 removes anyway.

**Tasks**:

- [ ] Split token generate/verify into a narrow interface (e.g. `domain.TokenService`, with middleware consuming only a `TokenVerifier` view)
- [ ] Update `AuthMiddleware` to depend on the narrow interface; drop `GenerateToken` from the public `AuthService` surface if 2.6.9 makes it internal
- [ ] Shrink mocks accordingly

**Files to modify**:

- `internal/domain/auth.go`
- `internal/middlewares/auth_middleware.go`
- `internal/services/auth_service.go`
- `internal/mocks/*`

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
