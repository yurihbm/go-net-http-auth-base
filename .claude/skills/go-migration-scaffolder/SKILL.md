---
name: go-migration-scaffolder
description: Guides database schema and sqlc query changes in this Go API, either by editing the initial migration (while the repository is a template) or by scaffolding a new migration and query file with a script. Use when asked to add or change a table, column or index, create a migration, or add a sqlc query.
---

# Go Migration Scaffolder

Tables use a `uuid uuid DEFAULT uuidv7()` primary key and `created_at`/`updated_at` timestamps, like `users` in `postgres/migrations/000001_init_db.up.sql`. Queries live in `postgres/queries/*.sql`; the Go code generated from them (`postgres/*.sql.go`, `models.go`) is only changed through `make sqlc-gen`.

## Choose the Workflow

Check `AGENTS.md`: while it has the "Template Phase" rule, use the template workflow, because a template ships a single initial migration (ADR-003). Otherwise use the migration workflow.

## Template Workflow

Edit the existing files instead of running the script (it always creates a new migration):

```
- [ ] 1. Add the DDL to postgres/migrations/000001_init_db.up.sql
- [ ] 2. Add the matching DROP to 000001_init_db.down.sql, in reverse dependency order
- [ ] 3. Write the queries in postgres/queries/
- [ ] 4. make migrate-down && make migrate-up (drops the local data)
- [ ] 5. make sqlc-gen
- [ ] 6. New table: add it to every truncateTables (see .claude/rules/repositories.md)
- [ ] 7. make check
```

## Migration Workflow

Scaffold the migration and an empty query file:

```bash
npx tsx .claude/skills/go-migration-scaffolder/scripts/create-migration.ts <migration_name>
```

For `add_products_table` it runs `make migrate-create name=add_products_table`, creates `postgres/queries/products.sql` if missing and prints the created paths. Then:

```
- [ ] 1. Write the DDL in the new .up.sql
- [ ] 2. Write the revert in the new .down.sql, so make migrate-down restores the previous schema
- [ ] 3. Write the queries in the query file
- [ ] 4. make migrate-up && make sqlc-gen
- [ ] 5. New table: add it to every truncateTables (see .claude/rules/repositories.md)
- [ ] 6. make check
```

## Query Format

```sql
-- name: CreateProduct :one
INSERT INTO products (name) VALUES (@name) RETURNING *;

-- name: GetProductByUUID :one
SELECT * FROM products WHERE uuid = @uuid;
```

## Validate

`make sqlc-gen` fails on SQL that does not match the schema; fix the query or the DDL and run it again. Finish with `make check`, which also fails if the committed generated code differs from the queries.
