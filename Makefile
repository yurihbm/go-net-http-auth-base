ifneq (,$(wildcard .env))
	include .env
	export
endif

AIR_VERSION = v1.62.0
SQLC_VERSION = v1.30.0
GOLANG_MIGRATE_VERSION = v4.19.0

.PHONY: install-tools install-air install-migrate install-sqlc tidy setup build migrate-create migrate-up migrate-down sqlc-gen

install-tools: install-air install-migrate install-sqlc

install-air:
	go install github.com/air-verse/air@$(AIR_VERSION)

install-migrate:
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@$(GOLANG_MIGRATE_VERSION)

install-sqlc:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

tidy:
	go mod tidy


setup: install-tools tidy

# Build application binary
build:
	@echo "Building application binary..."
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

