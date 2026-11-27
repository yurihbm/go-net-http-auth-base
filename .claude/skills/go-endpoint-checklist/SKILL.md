---
name: go-endpoint-checklist
description: Walks through adding an HTTP endpoint to an existing resource in this Go API, from the domain DTO and service method to the handler, route guards, Swagger, docs and tests, finishing with make check. Use when asked to add a route, endpoint or handler to a controller that already exists (users, auth, audit); for a new resource, use go-resource-scaffolder instead.
---

# Add an Endpoint to an Existing Resource

Work through the checklist in order and keep it in your reply, ticking items as they are done. Start each code step with a failing test (TDD). Skip an item only when it does not apply, and say why.

```
- [ ] 1. Domain: DTO with validate tags, service interface method, error keys
- [ ] 2. Mock: method on the service mock in internal/mocks
- [ ] 3. Service: implementation and unit tests
- [ ] 4. Repository and queries, if new persistence is needed
- [ ] 5. Handler with swag annotations and controller tests
- [ ] 6. Route in RegisterRoutes with the right guards
- [ ] 7. Wiring: new controller dependencies in the factory and dependencies.go
- [ ] 8. Docs: ERRORS.md, AUDIT.md, AUTH.md
- [ ] 9. Integration or E2E test, if the criteria apply
- [ ] 10. make swagger-gen, then make check
```

## 1. Domain

- Request DTOs live in the resource's file in `internal/domain` (e.g. `RequestEmailChangeDTO` in `users.go`, `CodeDTO` in `auth.go`) with `validate:"..."` tags and `json` tags. Update DTOs use pointer fields.
- Add the method to the service interface in `internal/domain`. Services take `ctx` first, DTOs and entities by value, and return pointers.
- New errors use the constructors in `internal/domain/errors.go` with dot-separated keys (`users.emailChange.cooldown`).

## 2. Mock

Add the method to the existing mock in `internal/mocks` (e.g. `UsersServiceMock`), following its style: `ctx` left out of `m.Called(...)`, nil check before the type assertion.

## 3. Service

Follow `.claude/rules/services.md`: business rules and authorization (`Actor.CanAccess`) in the service, `s.now()` instead of `time.Now()`, `WithinTx(ctx, func(ctx context.Context) error {...})` with the closure parameter named `ctx` when several writes must be atomic. Unit tests are `Test<Type>_<Method>` with `"success"` and `"error - ..."` subtests and the fixed `testClock`.

## 4. Persistence

For new queries, follow the `go-migration-scaffolder` skill and `.claude/rules/repositories.md`, then add repository integration tests.

## 5. Handler

- One handler method on the controller: `api.DecodeAndValidate[T](r)`, one service call, `api.HandleError(r.Context(), w, err)` on error, `api.WriteJSONResponse` with a message key (`users.emailChange.requested`) on success. Read the caller with `actorFromRequest(r)` and `sessionFromRequest(r)`.
- Audited actions call `auditResult` (or `auditLog`) from `audit_helpers.go` with a new or existing `domain.AuditAction...` constant from `internal/domain/audit.go`.
- Swag annotations above the handler, like `RequestEmailChange` in `users_controller.go`: `@Summary`, `@Description` (state the required cookies and step-up), `@Tags`, `@Accept`/`@Produce`, `@Param`, one `@Success` and one `@Failure` per status with its error keys, `@Router`.
- Controller tests in `<resource>_controller_test.go` (`package controllers_test`) build requests with `getControllerArgs` and cover success, validation error and each service error.

## 6. Route Guards

Register the route in the controller's `RegisterRoutes` with a Go 1.22 method pattern and wrap the handler in this order, outermost first:

1. `c.credentialsLimiter.Use(...)` when the route takes credentials, verifies a code or a token from an email, or sends an email (`POST /auth/login`, `POST /users`, `POST /auth/step-up`, the password reset routes). Refresh, logout and the OAuth redirects stay outside it (ADR-015). List the new route in the credential limiter paragraph of `docs/AUTH.md`.
2. `c.authMiddleware.Use(...)` for any signed-in route.
3. `c.stepUpMiddleware.Use(...)` for sensitive actions (email or password change, account deletion), or `c.adminRoleMiddleware.Use(...)` for admin-only routes.

Example: `router.HandleFunc("POST /auth/step-up/verify", c.credentialsLimiter.Use(c.authMiddleware.Use(c.VerifyStepUp)))`.

## Middleware Conventions

Read this only when the endpoint needs a new middleware or a header change.

- Per-route middlewares implement `middlewares.HandlerMiddleware` (`Use(http.HandlerFunc) http.HandlerFunc`) and are injected into controllers; global ones implement `middlewares.GlobalMiddleware` (`Use(http.Handler) http.Handler`). Each has a constructor, a `<name>_factory.go` in `internal/factories` and tests next to it; controller tests use `mocks.AuthMiddlewareMock`.
- The global chain is built in `NewHandler` (`internal/factories/handler.go`). When it changes, update the order listed in ADR-005 and `.claude/rules/telemetry.md` in the same change.
- `SecurityHeadersMiddleware` sets a deny-all CSP on every response. A handler that serves HTML or scripts sets its own `Content-Security-Policy`, as `DocsController` does with `swaggerCSP` (ADR-015).

## 7. Wiring

When the handler needs a service the controller does not have yet, add it to the controller struct and constructor, pass it in the controller's factory (`internal/factories/<resource>_factory.go`) from `*Dependencies`, and build it once in `NewDependencies` (`dependencies.go`) if it is new. Update the constructor calls in the controller tests.

## 8. Docs

- `docs/ERRORS.md`: every new error key, in the section of its area.
- `docs/AUDIT.md`: every new audit action, in the Actions list with its route.
- `docs/AUTH.md`: route, status codes, limits and cookies when the endpoint is part of an auth flow (sign-up, OAuth, sessions, step-up, email change, password). A security model change needs an ADR.

## 9. Integration and E2E Tests

Apply `.claude/rules/testing.md`:

- Integration test in `internal/tests/integration` when the service method runs a transaction (force a failure, assert nothing was persisted).
- E2E test in `internal/tests/e2e` when the behavior spans several requests with client-carried state (cookies, rotated tokens, emailed codes or links), depends on the production wiring (middleware chain, step-up or role guards, cookie attributes), or is a security invariant across the stack. A new guarded route usually gets a case in `authorization_test.go`. Single-request validation and error mapping stay in unit tests.

## 10. Validate

Run `make swagger-gen` and commit `docs/swagger/`, then `make check` (build, vet, lint, every test, Swagger and sqlc drift; needs Docker). Fix any failure and run it again until it passes.
