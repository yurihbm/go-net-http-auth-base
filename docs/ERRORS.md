# Error Handling Architecture

This document describes the error handling strategy implemented in the project. The architecture follows a strict 3-layered pattern where errors are transformed at the boundaries to ensure clean separation of concerns.

## Error Handling Philosophy

### Layer Responsibilities & Trust Chain

```
Repository → Service → Controller → HTTP Response
   │            │           │
   │            │           └─ HandleError() maps domain errors to HTTP status
   │            │
   │            └─ Trusts repo errors, only creates domain errors for:
   │               • Business rules (e.g., only self or admin can access a user)
   │               • External services (e.g., OAuth user info fetch failed)
   │               • Orchestration logic (e.g., OAuth state/provider mismatch)
   │
   └─ Transforms infrastructure errors (pgx, pgconn) → domain errors
```

**Key principles:**

1.  **Repository layer**: Maps **infrastructure errors** → **domain errors**
    - `pgx.ErrNoRows` → `domain.NotFoundError`
    - `pgconn.PgError` (code 23505) → `domain.ConflictError`
    - Unknown DB errors → `domain.InternalServerError`

2.  **Service layer**: Handles **business logic errors** + propagates repo errors
    - Business validation failures → `domain.ValidationError`
    - Authentication failures → `domain.UnauthorizedError`
    - Authorization failures (e.g. `Actor.CanAccess`) → `domain.ForbiddenError`
    - Pass-through repository domain errors **unchanged** (no re-wrapping)

3.  **Controller layer**: Maps **domain errors** → **HTTP responses**
    - Input decoding/validation via `api.DecodeAndValidate[T](r)` → `domain.ValidationError`
    - Calls `api.HandleError(ctx, w, err)` — no manual status code selection
    - `HandleError` uses `errors.As()` to detect the error type; unknown errors default to 500 Internal Server Error

## Domain Error Types

Defined in `internal/domain/errors.go`, these types represent **what** went wrong, independent of **how** it is presented.

| Error Type            | HTTP Status | Description                                      |
| :-------------------- | :---------- | :----------------------------------------------- |
| `NotFoundError`       | 404         | Resource not found (e.g., User not found)        |
| `ValidationError`     | 400         | Invalid input (supports field-level details)     |
| `ConflictError`       | 409         | State conflicts (e.g., Email already exists)     |
| `UnauthorizedError`   | 401         | Authentication failures (missing/invalid token, bad credentials) |
| `ForbiddenError`      | 403         | Authenticated but not allowed (e.g., not self or admin, missing role) |
| `TooManyRequestsError` | 429       | Rate-style limits enforced by the domain (e.g., step-up code cooldown) |
| `InternalServerError` | 500         | Unexpected system failures. Wraps original error |

### Step-up and email change keys

| Key                                  | Type                   | Where                                                                  |
| :----------------------------------- | :--------------------- | :--------------------------------------------------------------------- |
| `auth.stepUp.cooldown`               | `TooManyRequestsError` | `SessionChallengeRepository.Upsert` (step-up): a code was already issued in the last 60s   |
| `auth.stepUp.noChallenge`            | `UnauthorizedError`    | `SessionChallengeRepository.Attempt` (step-up): no challenge, expired, or attempts exhausted |
| `auth.stepUp.internalServerError`    | `InternalServerError`  | Unexpected `SessionChallengeRepository` (step-up) failures                                 |
| `auth.stepUp.invalidCode`            | `UnauthorizedError`    | `StepUpService.VerifyCode`: the code does not match                    |
| `auth.stepUp.sessionRevoked`         | `UnauthorizedError`    | `StepUpService.VerifyCode`: 10 wrong codes on one session; the session is deleted |
| `auth.stepUp.userLocked`             | `TooManyRequestsError` | `StepUpService.RequestCode`, `UsersRepository.ReserveStepUpGuess` (`VerifyCode`): 20 wrong codes across the user's sessions in 24h |
| `auth.stepUp.required`               | `ForbiddenError`       | `StepUpMiddleware`: the session has no active step-up                  |
| `auth.stepUp.sendFailed`             | `InternalServerError`  | `StepUpService.RequestCode`: the code email could not be sent          |
| `auth.stepUp.codeGenerationFailed`   | `InternalServerError`  | `StepUpService.RequestCode`: the random source failed                  |
| `users.emailChange.staleToken`       | `UnauthorizedError`    | `EmailChangeService.ConfirmEmailChange` (the challenge's `email_version` no longer matches), `RevertEmailChange` (token email or `email_version` no longer matches), `UsersRepository.UpdateEmail` (`email_version` no longer matches) |
| `users.emailChange.noChallenge`      | `UnauthorizedError`    | `SessionChallengeRepository.Attempt` (email change): the session has no challenge, it expired, attempts are exhausted, or it was already used |
| `users.emailChange.invalidCode`      | `UnauthorizedError`    | `EmailChangeService.ConfirmEmailChange`: the code does not match (counted per new address) |
| `users.emailChange.cooldown`         | `TooManyRequestsError` | `SessionChallengeRepository.Upsert` (email change): a code was already issued for this session in the last 60s |
| `users.emailChange.sendFailed`       | `InternalServerError`  | `EmailChangeService.RequestEmailChange`: the code email could not be sent (the challenge is deleted) |
| `users.emailChange.codeGenerationFailed` | `InternalServerError` | `EmailChangeService.RequestEmailChange`: the random source failed |
| `users.emailChange.internalServerError` | `InternalServerError` | Unexpected `SessionChallengeRepository` (email change) failures |
| `users.emailChange.locked`           | `ConflictError`        | `EmailChangeService.RequestEmailChange`/`ConfirmEmailChange`, `UsersService.Delete`: the email changed less than 72h ago (`Delete` only blocks a user deleting their own account) |
| `users.password.unauthorized`        | `UnauthorizedError`    | `PasswordService.ChangePassword`: the actor has no user UUID |
| `users.password.hashingFailed`       | `InternalServerError`  | `PasswordService`: bcrypt could not hash the new password (reset or change) |
| `users.emailChange.unauthorized`     | `UnauthorizedError`    | `EmailChangeService.RequestEmailChange`/`ConfirmEmailChange`: the actor has no user UUID |
| `users.emailChange.unchanged`        | `ValidationError`      | `EmailChangeService.RequestEmailChange`: the new email equals the current one |

### Sign-up keys

| Key                                  | Type                   | Where                                                                  |
| :----------------------------------- | :--------------------- | :--------------------------------------------------------------------- |
| `auth.passwordReset.invalidCode`     | `UnauthorizedError`    | `PasswordResetRepository`, `UsersRepository.UpdatePassword`, `PasswordService.ResetPassword`: no `password_reset` cookie, unknown or malformed UUID, expired or exhausted reset, wrong code, already used, or the email changed since the request; all look the same on purpose |
| `auth.passwordReset.sendFailed`      | `InternalServerError`  | `PasswordService.RequestReset`: the code email could not be sent (the reset row is deleted) |
| `auth.passwordReset.codeGenerationFailed` | `InternalServerError` | `PasswordService.RequestReset`: the random source failed |
| `auth.passwordReset.internalServerError` | `InternalServerError` | Unexpected `PasswordResetRepository` failures |
| `auth.signup.noPending`              | `UnauthorizedError`    | `PendingSignupRepository`: no `pending_signup` cookie, unknown or malformed UUID, expired sign-up, code expired or attempts exhausted, or already consumed |
| `auth.signup.invalidCode`            | `UnauthorizedError`    | `PendingSignupService.Attempt`: the code does not match (counted per address) |
| `auth.signup.sendFailed`             | `InternalServerError`  | `PendingSignupService`: the code email could not be sent (on start the pending sign-up is deleted) |
| `auth.signup.codeGenerationFailed`   | `InternalServerError`  | `PendingSignupService`: the random source failed                       |
| `auth.signup.tokenGenerationFailed`  | `InternalServerError`  | `AuthService.CompleteSignup`: the session could not be started (the user is rolled back) |
| `auth.signup.internalServerError`    | `InternalServerError`  | Unexpected `PendingSignupRepository` failures                          |
| `users.create.passwordHashingFailed` | `InternalServerError`  | `PendingSignupService.StartCredentials`: bcrypt could not hash the password (the send reservation is not refunded) |
| `auth.email.sendLimit`               | `TooManyRequestsError` | `EmailSendLimiter.ReserveSend` (sign-up, email change): an email went to this address in the last 60s, or 5 in the last hour |
| `auth.email.codeLocked`              | `TooManyRequestsError` | `PendingSignupService.Attempt`/`EmailChangeService.ConfirmEmailChange`: 20 wrong codes for this address in 24h |
| `auth.email.internalServerError`     | `InternalServerError`  | Unexpected `EmailSendLimiter` failures                                 |
| `users.email.conflict`               | `ConflictError`        | `PendingSignupService.StartCredentials` and `AuthService.CompleteSignup`: the email belongs to an account or is reserved by a recent email change |

### Session and auth repository keys

| Key                                  | Type                   | Where                                                                  |
| :----------------------------------- | :--------------------- | :--------------------------------------------------------------------- |
| `sessions.notFound`                  | `NotFoundError`        | `SessionsRepository`: the session does not exist (or a compare-and-set on its `jti` matched no row) |
| `sessions.internalServerError`       | `InternalServerError`  | Unexpected `SessionsRepository` failures                               |
| `auth.internalServerError`           | `InternalServerError`  | Unexpected `AuthRepository` (OAuth provider links) failures            |

### Other keys

| Key | Type | Where |
| :-- | :-- | :-- |
| `auth.authenticate.invalidCredentials` | `UnauthorizedError` | `AuthService.CredentialsLogin`: unknown email or wrong password |
| `auth.authenticate.userFetchFailed` | `InternalServerError` | `AuthService.CredentialsLogin`: the user lookup failed unexpectedly |
| `auth.authenticate.tokenGenerationFailed` | `InternalServerError` | `AuthService.CredentialsLogin`: the session or tokens could not be created |
| `auth.oauthLogin.tokenGenerationFailed` | `InternalServerError` | `AuthService.OAuthLogin`: the session or tokens could not be created |
| `auth.oauthLogin.missingCodeVerifier` | `UnauthorizedError` | `AuthService.OAuthLogin`: the PKCE code verifier cookie is missing |
| `auth.oauthLogin.nonceMismatch` | `UnauthorizedError` | `AuthService.OAuthLogin`: the browser nonce does not match the state token |
| `auth.oauthLogin.providerMismatch` | `UnauthorizedError` | `AuthService.VerifyOAuthState`: the state token was issued for another provider |
| `auth.oauthLink.staleToken` | `UnauthorizedError` | `AuthService.RevertOAuthLink`: the link the undo token points to no longer exists (already undone or removed) |
| `auth.oauthProvider.invalid` | `ValidationError` | `AuthService`: unknown OAuth provider |
| `auth.oauthProvider.userInfoFetchFailed` | `InternalServerError` | `AuthService.GetOAuthProviderUserInfo`: the provider user info request failed |
| `auth.oauthProvider.notFound` | `NotFoundError` | `AuthRepository`: no link for that provider and user |
| `auth.oauthProvider.conflict` | `ConflictError` | `AuthRepository`: the provider account is already linked |
| `auth.user.notFound` | `NotFoundError` | `AuthRepository`: the user of a provider link does not exist (foreign key) |
| `auth.providerCallback.invalidProvider` | `ValidationError` | `AuthController`: the provider path value is not a known provider |
| `auth.providerCallback.invalidStatePayload` | `ValidationError` | `AuthService.VerifyOAuthState`: the state payload has no valid `redirect_uri` |
| `auth.providerCallback.invalidUserInfo` | `ValidationError` | `AuthService`: the provider user info is incomplete or invalid |
| `auth.providerCallback.missingParams` | `ValidationError` | `AuthController` OAuth callback: `code` or `state` is missing |
| `auth.login.invalidRedirectUri` | `ValidationError` | `AuthController`: `redirect_uri` is not an allowed origin |
| `auth.refresh.missingRefreshToken` | `UnauthorizedError` | `AuthController.RefreshToken`: no refresh token cookie |
| `auth.refreshToken.tokenGenerationFailed` | `InternalServerError` | `AuthService.RefreshToken`: the new tokens could not be generated |
| `auth.invalidToken` | `UnauthorizedError` | `AuthService`/`TokenService`: the token is malformed, expired, has the wrong audience or no longer matches its session |
| `auth.verifyToken.invalidTokenSigningMethod` | `UnauthorizedError` | `TokenService.VerifyToken`: the token is not signed with HMAC |
| `auth.tokenGenerationFailed` | `InternalServerError` | `TokenService.GenerateToken`: signing failed |
| `auth.unauthorized` | `UnauthorizedError` | `AuthMiddleware`: missing or invalid access token cookie (written directly after `api.RecordError`, not through `HandleError`) |
| `auth.forbidden` | `ForbiddenError` | `RoleMiddleware`: the role is not allowed |
| `rateLimit.exceeded` | `TooManyRequestsError` | `RateLimitMiddleware` and the credentials limiter: the per-IP bucket is empty |
| `user.getMe.unauthorized` | `UnauthorizedError` | `UsersController.GetMe`: no user in the request context |
| `users.forbidden` | `ForbiddenError` | `Actor.CanAccess` in `UsersService`: not self or admin |
| `users.notFound` | `NotFoundError` | `UsersRepository` (no rows), `SessionsRepository` (foreign key): the user does not exist |
| `users.invalidUserUUID` | `ValidationError` | `UsersRepository`, `UsersController` (via `pathUUID`): the user UUID is malformed |
| `users.oauthProvider.invalidUUID` | `ValidationError` | `AuthRepository`: the user UUID of a provider link is malformed |
| `users.invalidCursor` | `ValidationError` | `UsersRepository.List`: the pagination cursor is malformed |
| `users.list.badRequest` | `ValidationError` | `UsersController.ListUsers`: invalid `limit`, `role` or `search` (invalid UTF-8 or NUL byte) query parameter |
| `user.internalServerError` | `InternalServerError` | `UsersRepository.Delete`: unexpected failure |
| `sessions.invalidUUID` | `ValidationError` | `SessionsRepository`, `SessionChallengeRepository`: the session UUID is malformed |
| `auth.signup.invalidUUID` | `ValidationError` | `PendingSignupRepository`: the pending sign-up UUID is malformed |
| `auth.passwordReset.invalidUUID` | `ValidationError` | `PasswordResetRepository.Create`: the reset UUID is malformed |
| `auditLogs.invalidActorUUID` | `ValidationError` | `AuditRepository`: the actor UUID filter is malformed |
| `auditLogs.invalidCursor` | `ValidationError` | `AuditRepository`: the pagination cursor is malformed |
| `auditLogs.internalServerError` | `InternalServerError` | Unexpected `AuditRepository` failures |
| `audit.list.badRequest` | `ValidationError` | `AuditController.List`: invalid `limit`, date or cursor query parameter |
| `request.invalid` | `ValidationError` | `api.DecodeAndValidate`: the body is not valid JSON of the expected shape |
| `request.validation_failed` | `ValidationError` | `api.DecodeAndValidate`: a field failed validation (details per field) |

## Implementation Details

### 1. Repository Layer (`internal/repositories/`)

Repositories catch database-specific errors and return `domain` errors. We use helper functions in `internal/repositories/helpers.go` to standardize this mapping.

**Helper Functions:**

- `isNoRowsError(err, message)`: Checks for `pgx.ErrNoRows`.
- `isConflictError(err, message)`: Checks for PostgreSQL error code `23505` (Unique Violation).
- `isForeignKeyViolationError(err, message)`: Checks for PostgreSQL error code `23503` (Foreign Key Violation).
- `parseUUID(uuidStr, message)`: Converts a string to `pgtype.UUID`, returning a domain error for invalid input.

**Example:**

```go
func (r *UsersPostgresRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
    user, err := r.q.GetUserByEmail(ctx, email)
    if err != nil {
        if noRowsErr := isNoRowsError(err, "users.notFound"); noRowsErr != nil {
            return nil, noRowsErr
        }
        return nil, domain.NewInternalServerError("users.internalServerError", err)
    }
    // ...
}
```

### 2. Service Layer (`internal/services/`)

Services handle business rules and propagate repository errors unchanged. Input shape (required fields, email format, password length) is already validated by the controller through `validate` struct tags.

**Example:**

```go
var errForbiddenUserAccess = domain.NewForbiddenError("users.forbidden")

func (s *usersService) GetByUUID(ctx context.Context, actor domain.Actor, uuid string) (*domain.User, error) {
    // Business rule
    if !actor.CanAccess(uuid) {
        return nil, errForbiddenUserAccess
    }

    // Propagate Repository Errors
    return s.repo.FindByUUID(ctx, uuid)
}
```

### 3. Controller Layer (`internal/controllers/`)

Controllers decode and validate input with `api.DecodeAndValidate[T]` (strict JSON: unknown fields and trailing data are rejected; then the `validate` struct tags run) and delegate every error to the centralized `api.HandleError` function.

**Example:**

```go
func (c *UsersController) CreateUser(w http.ResponseWriter, r *http.Request) {
    dto, err := api.DecodeAndValidate[domain.CreateUserDTO](r)
    if err != nil {
        api.HandleError(r.Context(), w, err)
        return
    }

    user, err := c.userService.Create(r.Context(), dto)
    if err != nil {
        api.HandleError(r.Context(), w, err)
        return
    }
    // ...
}
```

### 4. API Layer (`internal/api/errors.go`)

The `HandleError` function inspects the error type using `errors.As()` and writes the appropriate JSON response.

**Response Format:**

```json
{
  "data": null,
  "error": "request.validation_failed",
  "details": {
    "field_name": "error description"
  }
}
```

`error` is always a dot-separated message key. For a `500`, the body only carries the key (e.g. `users.internalServerError`), never the wrapped cause.

The OAuth callback (`GET /auth/{provider}/callback`) is the exception: once the state token and browser nonce verify and the `redirect_uri` is allow-listed, failures redirect (`302`) to it with `?error=<code>` instead of a JSON body. The codes are the standard provider codes (`access_denied`, `invalid_request`, `unauthorized_client`, `unsupported_response_type`, `invalid_scope`, `server_error`, `temporarily_unavailable`), `verification_limited`, and for a failed login `missing_code_verifier`, `account_conflict`, `invalid_user_info` and `server_error`. Without a trusted redirect the error is JSON as above.

## Error Logging & Observability

We use a **Canonical Log Line** pattern to ensure observability without log spam.

### How it works

1.  **Context Injection**:
    When `api.HandleError(ctx, w, err)` is called, it stores the error in the request's `shared.RequestContextData` (put in the context by `RequestContextDataMiddleware`). For an `InternalServerError` it stores the unwrapped cause.

    ```go
    // internal/api/errors.go
    if hasReqContextData {
        reqContextData.Error = err
    }
    ```

2.  **Middleware Logging**:
    The `LoggerMiddleware` wraps the entire request. When the request finishes, it reads the error from the context and logs it alongside the request metadata.
    ```go
    // internal/middlewares/logger_middleware.go
    if reqContextData.Error != nil {
        attrs = append(attrs, slog.String("error", reqContextData.Error.Error()))
    }
    ```

### Benefits

- **Root Cause Visibility**: The `InternalServerError` type wraps the original infrastructure error (e.g., PostgreSQL connection failure), so the log entry contains the actual cause of the failure.
- **Single Log Entry**: Access logs and error logs are combined, making it easy to correlate HTTP status codes with their underlying errors.
- **Contextual**: Every error is automatically associated with the `requestUUID` and `userUUID` of the request log line.
- **Traces**: When telemetry is enabled, `TelemetryMiddleware` also records the stored error on the request span as an `exception` event.
