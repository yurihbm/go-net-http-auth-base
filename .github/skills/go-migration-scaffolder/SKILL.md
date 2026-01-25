---
name: go-migration-scaffolder
description: 'Helps with database migrations and queries. Use when asked to "add a table", "modify schema", "create migration", or "add sqlc query".'
---

# Go Migration Scaffolder

This skill streamlines the workflow for modifying the database schema and adding queries in this project.

## Capabilities

- Scaffolds new database migrations (`postgres/migrations/`)
- Scaffolds new query files (`postgres/queries/`)
- Automates the `make` commands for creating and applying migrations

## Usage

### 1. Scaffold Migration and Query Files

Run the `create-migration.ts` script to generate the necessary files.

```bash
npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts <migration_name>
```

**Example:**
```bash
npx tsx .github/skills/go-migration-scaffolder/scripts/create-migration.ts add_products_table
```

This will:
1.  Run `make migrate-create name=add_products_table`
2.  Create a corresponding empty query file: `postgres/queries/products.sql` (if it doesn't exist)
3.  Output the paths of the created files.

### 2. Implement SQL (Agent Task)

After running the script, the Agent (you) should:
1.  **Edit the `.up.sql` file**: Add the DDL (CREATE TABLE, ALTER TABLE, etc.) based on the user's request.
2.  **Edit the `.down.sql` file**: Add the DDL to revert the changes (DROP TABLE, etc.). This is critical for rollbacks.
3.  **Edit the `queries/*.sql` file**: Add the necessary queries (formatted for sqlc).
    ```sql
    -- name: CreateProduct :one
    INSERT INTO products (...) VALUES (...) RETURNING *;
    ```

### 3. Apply and Generate

Once the SQL is written, run:

```bash
make migrate-up && make sqlc-gen
```
