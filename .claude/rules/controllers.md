---
paths:
  - "internal/controllers/**"
  - "internal/api/**"
---

# Controllers Layer (`internal/controllers/`)

Controllers handle HTTP requests and responses. Key patterns:

- **Constructor Pattern**: Each controller is initialized with a constructor function (e.g., `NewUsersController`) that accepts dependencies via dependency injection.
- **Interface Implementation**: Controllers implement the `Controller` interface which requires a `RegisterRoutes(*http.ServeMux)` method.
- **Route Registration**: Routes are registered using Go 1.22+ HTTP method-specific patterns (e.g., `POST /users`, `GET /users/{uuid}`).
- **Middleware Integration**: Controllers receive middleware instances and apply them using the `Use()` method on protected routes.
- **Request Handling**:
  - Use `api.DecodeAndValidate[T](r)` to decode (strict JSON parsing, single-object body) and validate DTOs against their `validate` struct tags in one step.
  - Extract path parameters using `r.PathValue("param")`.
  - Extract context values (e.g., authenticated user UUID) using `r.Context().Value(key)`.
- **Validation**: `internal/api/request.go` wires a single `go-playground/validator` instance used by `DecodeAndValidate`. Decode or validation failures return a `domain.ValidationError` with per-field `details`, mapped to `400` by `internal/api/errors.go`. DTOs declare rules via `validate:"..."` tags (e.g., `validate:"required,email"`) in `internal/domain/*.go`.
- **Response Handling**:
  - Use `api.WriteJSONResponse()` helper for consistent JSON responses (format defined in `internal/api/response.go`).
  - Include appropriate HTTP status codes (201 for creation, 204 for deletion, etc.).
  - Use message keys (e.g., `"user.create.success"`) for i18n support.
  - Return error details in the `Error` field of the response body.
- **Error Handling**: Map service errors to appropriate HTTP status codes (400 for bad request, 404 for not found, 500 for internal errors).
- **Thin Handlers**: Decode input, call one service method, then handle the HTTP concerns (cookies, redirect, audit log).
- **API Docs (Swagger)**: Every handler carries swaggo/swag annotations (Swagger 2.0, general info in `cmd/main.go`). Run `make swagger-gen` after changing them: it regenerates `docs/swagger/` (committed), and CI fails on drift. `DocsController` serves Swagger UI in every environment: `/swagger/` (exact) is a public login gate (embedded static page that checks `GET /users/me`, refreshes once, or signs in via `POST /auth/login`, then goes to `/swagger/index.html`), and everything else under `/swagger/` (UI, `doc.json`) is behind the auth and admin role middlewares. Auth is cookie-only, which Swagger 2.0 cannot express, so there are no `securityDefinitions`; "Try it out" works because the browser sends the `access_token` cookie. The UI top bar has a Logout button, and a successful "Try it out" `POST /auth/logout` also returns to the gate (injected via `httpSwagger.AfterScript`/`UIConfig` from `assets/swagger_ui_*.js`).

**Example Structure**:

```go
type UsersController struct {
    userService          domain.UsersService
    emailChangeService   domain.EmailChangeService
    pendingSignupService domain.PendingSignupService
    auditService         domain.AuditService
    authMiddleware       middlewares.HandlerMiddleware
    stepUpMiddleware     middlewares.HandlerMiddleware
    isSecureCookie       bool
}

var _ Controller = (*UsersController)(nil)

func NewUsersController(
    service domain.UsersService,
    emailChangeService domain.EmailChangeService,
    pendingSignupService domain.PendingSignupService,
    auditService domain.AuditService,
    authMiddleware middlewares.HandlerMiddleware,
    stepUpMiddleware middlewares.HandlerMiddleware,
    isSecureCookie bool,
) *UsersController {
    return &UsersController{
        userService:          service,
        emailChangeService:   emailChangeService,
        pendingSignupService: pendingSignupService,
        auditService:         auditService,
        authMiddleware:       authMiddleware,
        stepUpMiddleware:     stepUpMiddleware,
        isSecureCookie:       isSecureCookie,
    }
}

func (c *UsersController) RegisterRoutes(router *http.ServeMux) {
    router.HandleFunc("POST /users", c.CreateUser)
    router.HandleFunc("GET /users/me", c.authMiddleware.Use(c.GetMe))
}

// factories/users_factory.go
func UsersFactory(deps *Dependencies, cfg *config.Config) controllers.Controller {
    return controllers.NewUsersController(
        deps.UsersService,
        deps.EmailChangeService,
        deps.PendingSignupService,
        deps.AuditService,
        deps.AuthMiddleware,
        deps.StepUpMiddleware,
        !cfg.IsDevelopment(),
    )
}
```
