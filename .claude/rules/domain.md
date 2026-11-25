---
paths:
  - "internal/domain/**"
---

# Domain Layer (`internal/domain/`)

- Interfaces: All service and repository interfaces are defined in the `domain` package. Add a mock for each new interface in `internal/mocks/`.
- DTOs: Data Transfer Objects are defined for create and update operations (e.g., `CreateUserDTO`, `UserUpdateDTO`).
- Pointer Fields: Update DTOs use pointer fields to distinguish between "not provided" and "set to zero value".
- Domain Models: Core entities (e.g., `User`) are defined in the domain package with all necessary fields.
- Enums: Use typed constants for enums (e.g., `UserRole` with `RoleAdmin`/`RoleUser`, `TokenAudience`, `OAuthProviderName`).
- Validation Tags: Request DTOs declare their input rules with `validate:"..."` tags (e.g., `CreateUserDTO.Password` is `validate:"required,min=8"`). Run `make swagger-gen` when a DTO used by a handler changes.
- Errors: Domain errors (`internal/domain/errors.go`) carry dot-separated keys (e.g., `"users.email.conflict"`); document new keys in `docs/ERRORS.md`.
- No Telemetry: `domain` never imports `go.opentelemetry.io/otel*`.
