---
name: go-resource-scaffolder
description: 'Scaffolds a new resource (Controller, Service, Repository, Domain, Factory) for the Go REST API project. Use when asked to "create a new resource", "add a new entity", "scaffold a vertical slice" or "generate a new API endpoint".'
---

# Go Resource Scaffolder

This skill generates the boilerplate code for a new resource in the layered architecture of the `go-net-http-auth-base` project.

## Capabilities

- Generates Domain Model and Interface (`internal/domain/<resource>.go`)
- Generates Repository implementation (`internal/repositories/<resource>_repository.go`)
- Generates Service implementation (`internal/services/<resource>_service.go`)
- Generates Controller implementation (`internal/controllers/<resource>_controller.go`)
- Generates Factory for dependency injection (`internal/factories/<resource>_factory.go`)
- Generates Unit Tests for Service and Controller
- Generates Integration Tests for Repository (`internal/repositories/<resource>_repository_test.go`)

## Usage

To scaffold a new resource, run the `scaffold.ts` script provided in the `scripts` directory.

### Command

```bash
npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName>
```

### Example

```bash
npx tsx .github/skills/go-resource-scaffolder/scripts/scaffold.ts Product
```

This will create:
- `internal/domain/product.go`
- `internal/repositories/product_repository.go`
- `internal/services/product_service.go`
- `internal/controllers/product_controller.go`
- `internal/factories/product_factory.go`
- `internal/repositories/product_repository_test.go` (Integration Tests)

## Next Steps After Scaffolding

1.  **Database**: Create the migration and sqlc queries (manual step or separate skill).
2.  **Wiring**: Register the new routes in `cmd/main.go`.
    ```go
    // cmd/main.go
    factories.ProductFactory(conn).RegisterRoutes(mux)
    ```
