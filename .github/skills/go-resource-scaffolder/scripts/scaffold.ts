import fs from 'fs';
import path from 'path';

// Parse arguments
const args = process.argv.slice(2);
const resourceNameArg = args.find(arg => !arg.startsWith('-'));
const isSingular = args.includes('--singular') || args.includes('-s');

if (!resourceNameArg) {
    console.error("Usage: npx tsx scaffold.ts <ResourceName> [--singular|-s]");
    console.error("Example: npx tsx scaffold.ts Product");
    console.error("Example: npx tsx scaffold.ts Auth --singular");
    process.exit(1);
}

// Helper functions for casing
function capitalize(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function camelize(str: string): string {
    return str.charAt(0).toLowerCase() + str.slice(1);
}

function pluralize(str: string): string {
    if (str.endsWith('y')) {
        return str.slice(0, -1) + 'ies';
    }
    return str + 's';
}

const Resource = capitalize(resourceNameArg);
const resource = camelize(resourceNameArg);
let Resources = pluralize(Resource);
let resources = pluralize(resource);

if (isSingular) {
    Resources = Resource;
    resources = resource;
}

console.log(`Scaffolding resource: ${Resource} (Plural/File Base: ${resources})`);

// Define paths
const rootDir = process.cwd();
const dirs = {
    domain: path.join(rootDir, 'internal', 'domain'),
    repositories: path.join(rootDir, 'internal', 'repositories'),
    services: path.join(rootDir, 'internal', 'services'),
    controllers: path.join(rootDir, 'internal', 'controllers'),
    factories: path.join(rootDir, 'internal', 'factories'),
    mocks: path.join(rootDir, 'internal', 'mocks'),
};

const templatesDir = path.join(__dirname, '..', 'templates');

// Ensure directories exist
for (const dir of Object.values(dirs)) {
    if (!fs.existsSync(dir)) {
        console.error(`Directory not found: ${dir}. Are you in the project root?`);
        process.exit(1);
    }
}

// Helper to load and replace template
function loadTemplate(filename: string, replacements: Record<string, string>): string {
    const templatePath = path.join(templatesDir, filename);
    if (!fs.existsSync(templatePath)) {
        throw new Error(`Template not found: ${templatePath}`);
    }

    let content = fs.readFileSync(templatePath, 'utf-8');

    // Perform replacements
    for (const [key, value] of Object.entries(replacements)) {
        // Replace {{Key}} with value globally
        const regex = new RegExp(`{{${key}}}`, 'g');
        content = content.replace(regex, value);
    }

    return content;
}

const replacements = {
    Resource,
    resource,
    Resources,
    resources,
};

// Files to create
try {
    const files = [
        {
            path: path.join(dirs.domain, `${resources}.go`),
            content: loadTemplate('domain.go.txt', replacements),
        },
        {
            path: path.join(dirs.repositories, `${resources}_repository.go`),
            content: loadTemplate('repository.go.txt', replacements),
        },
        {
            path: path.join(dirs.services, `${resources}_service.go`),
            content: loadTemplate('service.go.txt', replacements),
        },
        {
            path: path.join(dirs.controllers, `${resources}_controller.go`),
            content: loadTemplate('controller.go.txt', replacements),
        },
        {
            path: path.join(dirs.factories, `${resources}_factory.go`),
            content: loadTemplate('factory.go.txt', replacements),
        },
        {
            path: path.join(dirs.mocks, `${resources}_repository_mock.go`),
            content: loadTemplate('repository_mock.go.txt', replacements),
        },
        {
            path: path.join(dirs.mocks, `${resources}_service_mock.go`),
            content: loadTemplate('service_mock.go.txt', replacements),
        },
        {
            path: path.join(dirs.services, `${resources}_service_test.go`),
            content: loadTemplate('service_test.go.txt', replacements),
        },
        {
            path: path.join(dirs.controllers, `${resources}_controller_test.go`),
            content: loadTemplate('controller_test.go.txt', replacements),
        },
        {
            path: path.join(dirs.repositories, `${resources}_repository_test.go`),
            content: loadTemplate('repository_test.go.txt', replacements),
        },
    ];

    // Write files
    files.forEach(file => {
        if (fs.existsSync(file.path)) {
            console.warn(`Skipping ${file.path}: File already exists.`);
        } else {
            fs.writeFileSync(file.path, file.content);
            console.log(`Created ${file.path}`);
        }
    });

    console.log("\nScaffolding complete!");
    console.log("Remember to:");
    console.log("1. Add the SQL migration.");
    console.log("2. Generate SQLC queries.");
    console.log(`3. Register the factory in cmd/main.go: factories.${Resources}Factory(conn).RegisterRoutes(mux)`);

} catch (error: any) {
    console.error("Error generating files:", error.message);
    process.exit(1);
}
