ifneq (,$(wildcard .env))
	include .env
# make keeps quotes as part of the value, so strip them to accept VAR="x" and VAR=x alike
ENV_VARS := $(shell sed -n 's/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}\([A-Za-z_][A-Za-z0-9_]*\)[[:space:]]*=.*/\2/p' .env)
$(foreach var,$(ENV_VARS),$(eval $(var) := $(subst ',,$(subst ",,$($(var))))))
	export
endif

AIR_VERSION = v1.65.3
SQLC_VERSION = v1.31.1
GOLANG_MIGRATE_VERSION = v4.19.1
SWAG_VERSION = v1.16.6

.PHONY: install-tools \
	install-air \
	install-migrate \
	install-sqlc \
	install-swag \
	tidy \
	setup \
	hooks \
	build \
	migrate-create \
	promote-admin \
	rename \
	migrate-up \
	migrate-down \
	sqlc-gen \
	swagger-gen \
	test-cover \
	show-cover \
	test-e2e \
	check

install-tools: install-air install-migrate install-sqlc install-swag

install-air:
	go install github.com/air-verse/air@$(AIR_VERSION)

install-migrate:
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@$(GOLANG_MIGRATE_VERSION)

install-sqlc:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

install-swag:
	go install github.com/swaggo/swag/cmd/swag@$(SWAG_VERSION)

tidy:
	go mod tidy

# Filters out packages that should be excluded from coverage
PACKAGES=$(shell go list ./... | grep -v -E 'postgres|domain|mocks|config|logger|cmd|docs')

test-cover:
	@echo "Running tests with coverage exclusions..."
	go test -race -coverpkg=$(shell echo $(PACKAGES) | tr " " ",") -coverprofile=coverage.out $(PACKAGES)
	@echo "Coverage report generated: coverage.out"

show-cover: test-cover
	go tool cover -func=coverage.out

# Run the E2E suite against an ephemeral PostgreSQL container (requires Docker)
test-e2e:
	@echo "Running E2E tests..."
	go test -count=1 -race ./internal/tests/e2e/...

setup: install-tools tidy

# Enable the versioned git hooks (opt-in, changes this clone's core.hooksPath)
hooks:
	git config core.hooksPath .githooks

# Build application binary (override with make build GOOS=darwin GOARCH=arm64)
build: GOOS ?= linux
build: GOARCH ?= amd64
build:
	@echo "Building application binary..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -o bin/app ./cmd/api
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -o bin/promote-admin ./cmd/promote-admin

# Create a new database migration
migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "Error: name variable is required. Usage: make migrate-create name=your_migration_name"; \
		exit 1; \
	fi
	@echo ">> Creating a new database migration: $(name)"
	migrate create -ext sql -dir postgres/migrations -seq $(name)

# Rebrand the template (module path, project name and title)
rename:
	@if [ -z "$(module)" ] || [ -z "$(name)" ] || [ -z "$(title)" ]; then \
		echo "Error: module, name and title are required. Usage: make rename module=github.com/acme/foo name=foo title=\"Foo API\""; \
		exit 1; \
	fi
	go run ./tools/rename -module "$(module)" -name "$(name)" -title "$(title)"

# Promote an existing user to admin
promote-admin:
	@if [ -z "$(email)" ]; then \
		echo "Error: email variable is required. Usage: make promote-admin email=user@example.com"; \
		exit 1; \
	fi
	go run ./cmd/promote-admin $(email)

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

# Run every pre-PR check: build, vet, lint, full tests (Docker) and generated code drift.
# sqlc needs a database with the schema, so the drift check uses a throwaway PostgreSQL container, like the sqlc-drift CI job.
check:
	go build ./...
	go vet ./...
	golangci-lint run ./...
	go test ./...
	$(MAKE) swagger-gen
	git diff --exit-code -- docs/swagger
	@echo "Checking sqlc generated code..."
	@set -e; \
	container=$$(docker run -d --rm -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=sqlc -p 127.0.0.1::5432 postgres:18-alpine); \
	trap 'docker stop $$container >/dev/null' EXIT; \
	for i in $$(seq 30); do docker exec $$container pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break; sleep 1; done; \
	url="postgres://postgres:postgres@$$(docker port $$container 5432/tcp | head -n 1)/sqlc?sslmode=disable"; \
	migrate -database "$$url" -path postgres/migrations up; \
	DATABASE_URL="$$url" sqlc diff

# Generate the Swagger spec from the handler annotations
swagger-gen:
	@echo "Generating Swagger docs..."
	swag init -g cmd/api/main.go -o docs/swagger --parseInternal --parseDependency
