---
paths:
  - "internal/services/**"
---

# Services Layer (`internal/services/`)

Services implement business logic. Key patterns:

- **Constructor Pattern**: Services are created using factory functions (e.g., `NewUserService`) that accept repository dependencies.
- **Interface Implementation**: Services implement domain interfaces (e.g., `domain.UsersService`).
- **Private Struct, Public Interface**: Service structs are lowercase (private), but implement uppercase (public) interfaces defined in the domain package.
- **Pointer Usage**: Services receive DTOs and entities by value and return pointers to entities (`*domain.User`), so a `nil` result pairs with an error.
- **Business Logic**:
  - Services orchestrate repository calls and apply business rules.
  - Password hashing is performed in the service layer using `bcrypt.GenerateFromPassword()`.
  - Input shape is validated in the controller (`api.DecodeAndValidate`); services enforce business rules (e.g., self-or-admin access through `Actor.CanAccess`, which returns a `ForbiddenError`).
  - Services perform partial updates by fetching existing entities, modifying only provided fields, then calling repository update.
- **Email Normalization**: Services always pass emails through the unexported `normalizeEmail` helper (`services/helpers.go`, trim + lowercase) before lookup or write; repositories receive already normalized emails; the database enforces a unique index on `lower(email)`.
- **Clock**: services never call `time.Now()`; they take a `now func() time.Time` as the last constructor parameter and call `s.now()` (ADR-016). The `now()` inside SQL stays database-side.
- **Transactions**: Use `domain.Transactor.WithinTx(ctx, func(ctx context.Context) error { ... })` when several repository calls must succeed or fail together; always name the closure parameter `ctx` (details in `.claude/rules/repositories.md`).
- **Error Handling**: Services return domain-specific errors with meaningful messages (e.g., `"users.forbidden"`). See `docs/ERRORS.md`.
- **Multi-Step Orchestration**: Flows spanning several steps and services (e.g., `AuthService.OAuthLogin`, which verifies the state token, resolves/creates the user via `UsersService`, links the OAuth provider, and mints tokens) are implemented as a single service method. Controllers stay thin: decode input, call the one service method, then handle the HTTP concerns (cookies, redirect, audit log).
- **Auth and Email Flows**: Sign-up, OAuth, sessions, step-up, email change and token interfaces are described in `docs/AUTH.md` (rule: `.claude/rules/auth.md`).

**Example Structure**:

```go
type pendingSignupService struct {
    pending    domain.PendingSignupRepository
    limiter    domain.EmailSendLimiter
    users      domain.UsersRepository
    transactor domain.Transactor
    emails     domain.EmailVerificationService
    hmacKey    []byte
}

func (s *pendingSignupService) StartCredentials(ctx context.Context, dto domain.CreateUserDTO) (string, error) {
    email := normalizeEmail(dto.Email)
    if err := s.ensureEmailAvailable(ctx, email); err != nil {
        return "", err
    }

    if err := s.reserveSend(ctx, email); err != nil {
        return "", err
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
    if err != nil {
        return "", domain.NewInternalServerError("users.create.passwordHashingFailed", err)
    }

    return s.start(ctx, domain.PendingSignup{
        Kind:         domain.PendingSignupKindCredentials,
        Name:         dto.Name,
        Email:        email,
        PasswordHash: string(hash),
    })
}
```
