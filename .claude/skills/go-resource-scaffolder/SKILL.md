---
name: go-resource-scaffolder
description: Scaffolds a new resource for this Go API as a vertical slice (domain model and interfaces, repository with integration tests, service and controller with unit tests, mocks, factory) from templates, then lists the wiring steps. Use when asked to create a new resource or entity, scaffold a vertical slice, or add endpoints for a resource that has no controller yet; to add an endpoint to an existing controller, use go-endpoint-checklist.
---

# Go Resource Scaffolder

## Run the Script

```bash
npx tsx .claude/skills/go-resource-scaffolder/scripts/scaffold.ts <ResourceName> [--singular|-s]
```

`<ResourceName>` is PascalCase (`Product`). File and type names are plural by default (`products_service.go`, `ProductsService`); `--singular` keeps them singular for inherently singular resources (`Auth` gives `auth_service.go`).

For `Product` it creates:

- `internal/domain/products.go`
- `internal/repositories/products_repository.go` and `products_repository_test.go`
- `internal/services/products_service.go` and `products_service_test.go`
- `internal/controllers/products_controller.go` and `products_controller_test.go`
- `internal/factories/products_factory.go`
- `internal/mocks/products_repository_mock.go` and `products_service_mock.go`

The generated code follows `AGENTS.md` and `.claude/rules/` (`ctx` first, `api.DecodeAndValidate` and `api.HandleError`, swag annotations, domain errors) and passes build, vet, lint and the unit tests as generated. The repository methods are placeholders returning an `InternalServerError`, so the repository integration tests fail until step 4.

## Next Steps

The script prints these steps with the names filled in. Copy the checklist into your reply and tick items as they are done:

```
- [ ] 1. Wire the service in dependencies.go
- [ ] 2. Register the factory in handler.go
- [ ] 3. Add the table to the schema and to every truncateTables
- [ ] 4. Write the queries, run make sqlc-gen, implement the repository
- [ ] 5. Add fields, rules and tests; run make swagger-gen
- [ ] 6. Run make check
```

1. Wiring: build the service once in `NewDependencies` (`internal/factories/dependencies.go`), on the shared `db`:
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
   A service that needs the clock takes `now func() time.Time` as its last constructor parameter and receives `time.Now` here (ADR-016).
2. Routes: add `ProductsFactory(deps).RegisterRoutes(mux)` in `NewHandler` (`internal/factories/handler.go`), next to the other factories. Pick the route guards as described in the `go-endpoint-checklist` skill.
3. Schema: while this repository is a template, add the table to `postgres/migrations/000001_init_db.up.sql` and its `DROP` to `.down.sql` (the `go-migration-scaffolder` skill has the workflow). Add the table to every `truncateTables`: `internal/repositories/repositories_test.go`, `internal/tests/integration/integration_test.go` and `internal/tests/e2e/helpers_test.go`.
4. Queries: write `postgres/queries/products_queries.sql`, run `make sqlc-gen`, and replace the placeholders in `products_repository.go` following `users_repository.go` (`parseUUID`, `isNoRowsError`, `isConflictError`, `domain.NewInternalServerError`, a `toProduct` mapper). The repository integration tests then pass.
5. Fields and rules: add the fields to the model and DTOs (`validate` tags on create DTOs, pointer fields on update DTOs), map them in the service, add authorization with `domain.Actor` if the resource is per owner, extend the tests, document new error keys in `docs/ERRORS.md`, and run `make swagger-gen`.
6. Validate: run `make check` and fix every failure until it passes.
