---
name: go-resource-scaffolder
description: 'Scaffolds a new resource (Controller, Service, Repository, Domain, Factory) for the Go REST API project. Use when asked to "create a new resource", "add a new entity", "scaffold a vertical slice" or "generate a new API endpoint".'
---

# Go Resource Scaffolder

This skill generates the boilerplate code for a new resource in the layered architecture of the `go-net-http-auth-base` project.

## Capabilities

- Generates Domain Model and Interface (`internal/domain/<resources>.go`)
- Generates Repository implementation (`internal/repositories/<resources>_repository.go`)
- Generates Service implementation (`internal/services/<resources>_service.go`)
- Generates Controller implementation (`internal/controllers/<resources>_controller.go`)
- Generates Factory for dependency injection (`internal/factories/<resources>_factory.go`)
- Generates Unit Tests for Service and Controller
- Generates Integration Tests for Repository (`internal/repositories/<resources>_repository_test.go`)

## Usage

To scaffold a new resource, run the `scaffold.ts` script provided in the `scripts` directory.

### Command

```bash
npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName> [--singular|-s]
```

### Options

- `<ResourceName>`: The name of the resource (e.g., `Product`, `User`).
- `--singular`, `-s`: Force singular naming for files and interfaces (e.g., `auth_service.go` instead of `auths_service.go`). Useful for resources that are inherently singular like `Auth`.

### Example

**Default (Plural naming - Recommended for entities):**

```bash
npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts Product
```

This will create:
- `internal/domain/products.go`
- `internal/repositories/products_repository.go`
- `internal/services/products_service.go`
- `internal/controllers/products_controller.go`
- `internal/factories/products_factory.go`
- `internal/repositories/products_repository_test.go`

**Singular naming:**

```bash
npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts Auth --singular
```

This will create:
- `internal/domain/auth.go`
- `internal/repositories/auth_repository.go`
- ...

## Next Steps After Scaffolding

1.  **Database**: Create the migration and sqlc queries (manual step or separate skill).
2.  **Wiring**: Register the new routes in `cmd/main.go`.
    ```go
    // cmd/main.go
    factories.ProductFactory(conn).RegisterRoutes(mux)
    ```
