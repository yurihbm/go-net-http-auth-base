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
- Generates testify mocks for the Service and Repository (`internal/mocks/<resources>_{service,repository}_mock.go`)
- Generates Unit Tests for Service and Controller
- Generates Integration Tests for Repository (`internal/repositories/<resources>_repository_test.go`)

The generated code follows the conventions in `AGENTS.md`: `context.Context` first on every service and repository method, `api.DecodeAndValidate` + `api.HandleError` in the controller, swag annotations on every handler, domain errors in the repository, and a factory that reads from `*factories.Dependencies`. It compiles and passes `go vet`, `golangci-lint` and the unit tests right away. The repository methods are placeholders that return an `InternalServerError` until the queries exist, so the repository integration tests fail until step 4 below.

## Usage

To scaffold a new resource, run the `scaffold.ts` script provided in the `scripts` directory.

### Command

```bash
npx tsx .claude/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName> [--singular|-s]
```

### Options

- `<ResourceName>`: The name of the resource (e.g., `Product`, `User`).
- `--singular`, `-s`: Force singular naming for files and interfaces (e.g., `auth_service.go` instead of `auths_service.go`). Useful for resources that are inherently singular like `Auth`.

### Example

**Default (Plural naming - Recommended for entities):**

```bash
npx tsx .claude/skills/go-resource-scaffolder/scripts/scaffold.ts Product
```

This will create:
- `internal/domain/products.go`
- `internal/repositories/products_repository.go`
- `internal/services/products_service.go`
- `internal/controllers/products_controller.go`
- `internal/factories/products_factory.go`
- `internal/mocks/products_repository_mock.go`, `internal/mocks/products_service_mock.go`
- `internal/services/products_service_test.go`, `internal/controllers/products_controller_test.go`
- `internal/repositories/products_repository_test.go`

**Singular naming:**

```bash
npx tsx .claude/skills/go-resource-scaffolder/scripts/scaffold.ts Auth --singular
```

This will create:
- `internal/domain/auth.go`
- `internal/repositories/auth_repository.go`
- ...

## Next Steps After Scaffolding

The script prints these steps with the resource names filled in.

1.  **Wiring**: Build the service once in the composition root, `internal/factories/dependencies.go`:
    ```go
    type Dependencies struct {
        // ...
        ProductsService domain.ProductsService
    }

    // in NewDependencies, before the return
    productsService := services.NewProductsService(repositories.NewProductsPostgresRepository(db))

    // in the returned literal
    ProductsService: productsService,
    ```
2.  **Routes**: Register the factory in `cmd/main.go`, next to the other factories:
    ```go
    factories.ProductsFactory(deps).RegisterRoutes(mux)
    ```
3.  **Schema**: While this repository is still a template, add the table to `postgres/migrations/000001_init_db.up.sql` (and its `DROP` to `.down.sql`) instead of a new migration file. Add the table to `truncateTables` in `internal/repositories/repositories_test.go`.
4.  **Queries**: Write `postgres/queries/products.sql`, run `make sqlc-gen`, and replace the placeholders in `products_repository.go` following `users_repository.go` (`parseUUID`, `isNoRowsError`, `isConflictError`, `domain.NewInternalServerError`, a `toProduct` mapper). The repository integration tests should then pass.
5.  **Fields and rules**: Add the fields to the domain model and the DTOs (`validate` tags on create DTOs, pointer fields on update DTOs), map them in the service, extend the tests, add authorization if the resource is per-owner (see `domain.Actor`), and run `make swagger-gen`.
