import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const migrationName = process.argv[2];

if (!migrationName) {
    console.error("Usage: npx tsx create-migration.ts <migration_name>");
    process.exit(1);
}

console.log(`Scaffolding migration for: ${migrationName}`);

try {
    // 1. Run make migrate-create
    // We assume the makefile is in the root.
    console.log("Running 'make migrate-create'...");
    const output = execSync(`make migrate-create name=${migrationName}`, { encoding: 'utf-8' });
    console.log(output);

    // 2. Identify the created file to find the timestamp
    // The make command typically outputs "postgres/migrations/YYYYMMDDHHMMSS_name.up.sql"
    // But verify by listing the migrations dir
    const migrationsDir = path.join('postgres', 'migrations');
    const files = fs.readdirSync(migrationsDir);
    
    // Find files matching the name and ending in .up.sql or .down.sql
    const createdFiles = files.filter(f => f.includes(migrationName) && (f.endsWith('.up.sql') || f.endsWith('.down.sql')));
    
    if (createdFiles.length === 0) {
        console.warn("Warning: Could not locate the created migration file automatically.");
    } else {
        // Sort by name (timestamp) desc to get the latest
        createdFiles.sort().reverse();
        // We expect at least an up and a down file
        const upMigration = createdFiles.find(f => f.endsWith('.up.sql'));
        const downMigration = createdFiles.find(f => f.endsWith('.down.sql'));

        if (upMigration) console.log(`Created UP migration file: ${path.join(migrationsDir, upMigration)}`);
        if (downMigration) console.log(`Created DOWN migration file: ${path.join(migrationsDir, downMigration)}`);
    }

    // 3. Create query file
    // Convention: If migration is "add_products_table", query file should be "products.sql"
    
    let queryFileName = migrationName;
    
    // Simple heuristics for cleaner query filenames
    if (queryFileName.startsWith('add_') && queryFileName.endsWith('_table')) {
        queryFileName = queryFileName.replace('add_', '').replace('_table', '');
    } else if (queryFileName.startsWith('create_') && queryFileName.endsWith('_table')) {
        queryFileName = queryFileName.replace('create_', '').replace('_table', '');
    }
    
    const queryFilePath = path.join('postgres', 'queries', `${queryFileName}.sql`);
    
    if (fs.existsSync(queryFilePath)) {
        console.log(`Query file already exists: ${queryFilePath}`);
    } else {
        fs.writeFileSync(queryFilePath, "-- name: Get" + capitalize(queryFileName) + " :one\n-- SELECT * FROM " + queryFileName + " WHERE id = $1;\n");
        console.log(`Created query file: ${queryFilePath}`);
    }

    console.log("\nSuccess! Next steps:");
    console.log("1. Add SQL DDL to the new UP migration file in postgres/migrations/");
    console.log("2. Add SQL DDL to the new DOWN migration file in postgres/migrations/ (to revert changes)");
    console.log(`3. Add SQL queries to ${queryFilePath}`);
    console.log("4. Run 'make migrate-up && make sqlc-gen'");

} catch (error: any) {
    console.error("Error executing command:", error.message);
    process.exit(1);
}

function capitalize(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
