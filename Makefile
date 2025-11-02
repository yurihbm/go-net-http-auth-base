include .env
export

TOOLS = \
	github.com/air-verse/air@v1.62.0 \
	github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0

.PHONY: install-tools tidy setup build migrate-create migrate-up migrate-down sqlc-gen

install-tools:
	@echo "Installing tools..."
	@for tool in $(TOOLS); do \
		echo "Installing $$tool..."; \
		go install $$tool; \
	done
	@echo "Installing github.com/golang-migrate/migrate/v4/cmd/migrate@v4.19.0..."
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.19.0

tidy:
	@echo "Tidying up go.mod and go.sum..."
	go mod tidy

setup: install-tools tidy

# Build production binary
build:
	@echo "Building production binary..."
	GOOS=linux GOARCH=amd64 go build -o bin/app ./cmd/main.go

# Create a new database migration
migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "Error: name variable is required. Usage: make migrate-create name=your_migration_name"; \
		exit 1; \
	fi
	@echo ">> Creating a new database migration: $(name)"
	migrate create -ext sql -dir postgres/migrations -seq $(name)

# Run database migrations
migrate-up:
	@echo "Running database migrations..."
	migrate -database $(DATABASE_URL) -path postgres/migrations up

# Run last database migration
migrate-down:
	@echo "Reverting last database migration..."
	migrate -database $(DATABASE_URL) -path postgres/migrations down 1

# Generate code with sqlc
sqlc-gen:
	@echo "Generating code with sqlc..."
	DATABASE_URL=$(DATABASE_URL) sqlc generate

