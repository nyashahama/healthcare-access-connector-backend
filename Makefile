.PHONY: help dev prod docker-up docker-down docker-logs db-migrate db-seed test clean build run sqlc mocks generate

# Variables
APP_NAME=healthcare-access-connector-backend
BINARY_NAME=api
MAIN_PATH=./cmd/api
DOCKER_IMAGE=$(APP_NAME):latest
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

# Load environment variables from .env file
ifneq (,$(wildcard .env))
    include .env
    export
endif

# Detect current environment from .env symlink
CURRENT_ENV := $(shell if [ -L .env ]; then \
	target=$(readlink .env); \
	if [ "$target" = ".env.production" ]; then \
		echo "production"; \
	else \
		echo "development"; \
	fi; \
else \
	echo "development"; \
fi)

# Set DB_URL from environment variable or use default
DB_URL ?= $(DATABASE_URL)

# Default target
help:
	@echo '${GREEN}Healthcare Access Connector - Development Commands${RESET}'
	@echo ""
	@echo "Development:"
	@echo "  make dev              - Run app in development mode (local services)"
	@echo "  make prod             - Run app in production mode (cloud services)"
	@echo "  make run              - Run app directly with go run"
	@echo ""
	@echo "Docker Services:"
	@echo "  make docker-up        - Start all local services (postgres, redis, mailpit, etc.)"
	@echo "  make docker-down      - Stop all local services"
	@echo "  make docker-logs      - View logs from all services"
	@echo "  make docker-clean     - Stop services and remove volumes"
	@echo "  make docker-rebuild   - Force rebuild and restart all services"
	@echo ""
	@echo "Database:"
	@echo "  make db-migrate       - Run database migrations (auto-detects environment)"
	@echo "  make db-migrate-dev   - Run migrations on development database"
	@echo "  make db-migrate-prod  - Run migrations on production database"
	@echo "  make db-seed          - Seed database with test data"
	@echo "  make migrate-up       - Run migrations (alias, auto-detects environment)"
	@echo "  make migrate-down     - Rollback last migration"
	@echo "  make migrate-create   - Create new migration (name=migration_name)"
	@echo "  make migrate-status   - Show migration status"
	@echo ""
	@echo "Testing:"
	@echo "  make test             - Run all tests"
	@echo "  make test-coverage    - Run tests with coverage"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make bench            - Run benchmarks"
	@echo ""
	@echo "Build:"
	@echo "  make build            - Build the application"
	@echo "  make clean            - Clean build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt              - Format code"
	@echo "  make lint             - Run linter"
	@echo "  make vet              - Run go vet"
	@echo "  make check            - Run all checks (fmt, lint, vet, test)"
	@echo ""
	@echo "Utilities:"
	@echo "  make generate-jwt     - Generate JWT secret"
	@echo "  make generate         - Generate sqlc code AND mocks (recommended)"
	@echo "  make sqlc             - Generate sqlc database code only"
	@echo "  make mocks            - Regenerate mocks from Querier interface only"
	@echo "  make tidy             - Tidy dependencies"
	@echo "  make install-tools    - Install development tools"
	@echo "  make env-status       - Show current environment"
	@echo "  make switch-dev       - Switch to development environment"
	@echo "  make switch-prod      - Switch to production environment"
	@echo ""
	@echo "Services URLs (when running locally):"
	@echo "  - Application:        http://localhost:8080"
	@echo "  - Mailpit UI:         http://localhost:8025"
	@echo "  - Redis:              localhost:6379"
	@echo "  - PostgreSQL:         localhost:5432"
	@echo "  - NATS:               localhost:4222"
	@echo ""
	@echo "Override database URL:"
	@echo "  make db-migrate DB_URL=\"your-connection-string\""

# Development mode - uses local services
dev: 
	@echo "${GREEN}Switching to DEVELOPMENT environment...${RESET}"
	@ln -sf .env.development .env
	@$(MAKE) docker-up
	@echo "${GREEN}Starting application in DEVELOPMENT mode...${RESET}"
	@echo "Using local PostgreSQL, Redis, and Mailpit"
	@sleep 3
	go run $(MAIN_PATH)/main.go

# Production mode - uses cloud services
prod:
	@echo "${GREEN}Switching to PRODUCTION environment...${RESET}"
	@ln -sf .env.production .env
	@echo "${GREEN}Starting application in PRODUCTION mode...${RESET}"
	@echo "Using Supabase, Upstash Redis, and Resend"
	go run $(MAIN_PATH)/main.go

# Run application directly
run:
	@echo "${GREEN}Running application...${RESET}"
	go run $(MAIN_PATH)/main.go

# Start all local services with Docker
docker-up:
	@echo "${GREEN}Starting local services...${RESET}"
	docker-compose up -d postgres redis nats mailpit
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@echo ""
	@echo "${GREEN}✓ Services started successfully!${RESET}"
	@echo ""
	@echo "Service URLs:"
	@echo "  - PostgreSQL:       localhost:5432 (postgres/admin)"
	@echo "  - Redis:            localhost:6379"
	@echo "  - Mailpit UI:       http://localhost:8025"
	@echo "  - NATS:             localhost:4222"

# Stop all local services
docker-down:
	@echo "${YELLOW}Stopping local services...${RESET}"
	docker-compose down

# View logs from all services
docker-logs:
	docker-compose logs -f postgres redis nats mailpit

# Stop services and remove volumes (clean slate)
docker-clean:
	@echo "${YELLOW}Stopping services and removing volumes...${RESET}"
	docker-compose down -v
	@echo "${GREEN}✓ Clean slate ready!${RESET}"

# Rebuild everything
docker-rebuild:
	@echo "${YELLOW}Removing old containers and images...${RESET}"
	docker-compose down -v
	@echo "${GREEN}Building fresh image (no cache)...${RESET}"
	docker-compose build --no-cache
	@echo "${GREEN}Starting services...${RESET}"
	docker-compose up -d
	@sleep 5
	@echo "${GREEN}✓ Rebuild complete!${RESET}"

# Database migrations - auto-detects environment
db-migrate:
	@if [ -z "$(DB_URL)" ]; then \
		echo "${YELLOW}Error: DB_URL not set in .env file${RESET}"; \
		echo "Please ensure DB_URL is set in your .env file"; \
		exit 1; \
	fi
	@echo "${GREEN}Running database migrations...${RESET}"
	@echo "Environment: ${YELLOW}$(CURRENT_ENV)${RESET}"
	@echo ""
	migrate -path database/migrations -database "$(DB_URL)" up

# Run migrations with confirmation for production
db-migrate-prod:
	@if [ ! -L .env ] || [ "$(readlink .env)" != ".env.production" ]; then \
		echo "${YELLOW}⚠️  Warning: .env is not pointing to .env.production${RESET}"; \
		echo "Run 'make switch-prod' first or use DB_URL override"; \
		exit 1; \
	fi
	@echo "${YELLOW}⚠️  WARNING: Running migrations on PRODUCTION database!${RESET}"
	@echo ""
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $REPLY =~ ^[Yy]$ ]]; then \
		$(MAKE) db-migrate; \
	else \
		echo "${YELLOW}Migration cancelled.${RESET}"; \
	fi

migrate-up: db-migrate

migrate-down:
	@if [ -z "$(DB_URL)" ]; then \
		echo "${YELLOW}Error: DB_URL not set in .env file${RESET}"; \
		exit 1; \
	fi
	@echo "${YELLOW}Warning: This will rollback the last migration${RESET}"
	@echo "Environment: ${YELLOW}$(CURRENT_ENV)${RESET}"
	@echo ""
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $REPLY =~ ^[Yy]$ ]]; then \
		migrate -path database/migrations -database "$(DB_URL)" down 1; \
	else \
		echo "${YELLOW}Rollback cancelled.${RESET}"; \
	fi

migrate-create:
	@if [ -z "$(name)" ]; then echo "${YELLOW}Error: name is required. Usage: make migrate-create name=migration_name${RESET}"; exit 1; fi
	@echo "${GREEN}Creating migration: $(name)${RESET}"
	migrate create -ext sql -dir database/migrations -seq $(name)

migrate-status:
	@if [ -z "$(DB_URL)" ]; then \
		echo "${YELLOW}Error: DB_URL not set in .env file${RESET}"; \
		exit 1; \
	fi
	@echo "${GREEN}Migration Status${RESET}"
	@echo "Environment: ${YELLOW}$(CURRENT_ENV)${RESET}"
	@echo ""
	migrate -path database/migrations -database "$(DB_URL)" version

# Seed database with test data
db-seed:
	@echo "${GREEN}Seeding database with test data...${RESET}"
	go run cmd/seed/main.go

# Generate sqlc code only
sqlc:
	@echo "${GREEN}Generating sqlc code...${RESET}"
	sqlc generate
	@echo "${GREEN}✓ sqlc code generated!${RESET}"

# Generate mocks from the sqlc Querier interface
mocks:
	@echo "${GREEN}Generating mocks...${RESET}"
	mockery
	@echo "${GREEN}✓ Mocks generated!${RESET}"

# Generate sqlc code AND mocks together (recommended - keeps them in sync)
generate: sqlc mocks
	@echo "${GREEN}✓ Code generation complete!${RESET}"

# Run tests
test:
	@echo "${GREEN}Running tests...${RESET}"
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

test-coverage:
	@echo "${GREEN}Running tests with coverage...${RESET}"
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "${GREEN}✓ Coverage report generated: coverage.html${RESET}"

test-unit:
	@echo "${GREEN}Running unit tests...${RESET}"
	go test -v -short ./...

test-integration:
	@echo "${GREEN}Running integration tests...${RESET}"
	go test -v -tags=integration ./tests/integration/...

bench:
	@echo "${GREEN}Running benchmarks...${RESET}"
	go test -bench=. -benchmem ./...

# Build application
build:
	@echo "${GREEN}Building application...${RESET}"
	CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/$(BINARY_NAME) $(MAIN_PATH)/main.go
	@echo "${GREEN}✓ Build complete: bin/$(BINARY_NAME)${RESET}"

# Clean build artifacts
clean:
	@echo "${YELLOW}Cleaning build artifacts...${RESET}"
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -rf tmp/
	@echo "${GREEN}✓ Clean complete!${RESET}"

# Format code
fmt:
	@echo "${GREEN}Formatting code...${RESET}"
	go fmt ./...
	@echo "${GREEN}✓ Code formatted!${RESET}"

# Lint code
lint:
	@echo "${GREEN}Linting code...${RESET}"
	golangci-lint run --timeout 5m

# Run go vet
vet:
	@echo "${GREEN}Running go vet...${RESET}"
	go vet ./...

# Tidy dependencies
tidy:
	@echo "${GREEN}Tidying dependencies...${RESET}"
	go mod tidy
	go mod verify
	@echo "${GREEN}✓ Dependencies tidied!${RESET}"

# Install development tools
install-tools:
	@echo "${GREEN}Installing development tools...${RESET}"
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/cosmtrek/air@latest
	go install github.com/vektra/mockery/v2@latest
	@echo "${GREEN}✓ Tools installed!${RESET}"

# Generate JWT secret
generate-jwt:
	@echo "${GREEN}Generated JWT Secret (copy to .env):${RESET}"
	@openssl rand -base64 32

# Run all checks
check: build vet test
	@echo "${GREEN}✓ All checks passed!${RESET}"

# CI pipeline
ci: tidy fmt lint vet test
	@echo "${GREEN}✓ CI pipeline complete!${RESET}"

# Quick start for first time setup
setup: install-tools
	@echo "${GREEN}Setting up development environment...${RESET}"
	@if [ ! -f .env.development ]; then echo "${YELLOW}Warning: .env.development not found${RESET}"; fi
	@if [ ! -f .env.production ]; then echo "${YELLOW}Warning: .env.production not found${RESET}"; fi
	@if [ ! -L .env ]; then ln -sf .env.development .env; echo "${GREEN}.env symlink created${RESET}"; fi
	@$(MAKE) docker-up
	@sleep 5
	@echo ""
	@echo "${GREEN}✓ Setup complete! Run 'make dev' to start the application.${RESET}"

# Environment management
env-status:
	@echo "${GREEN}Current Environment Status:${RESET}"
	@echo ""
	@if [ -L .env ]; then \
		target=$(readlink .env); \
		echo "  .env symlink → $target"; \
		if [ "$target" = ".env.development" ]; then \
			echo "  Environment: ${GREEN}DEVELOPMENT${RESET}"; \
		elif [ "$target" = ".env.production" ]; then \
			echo "  Environment: ${YELLOW}PRODUCTION${RESET}"; \
		fi; \
	elif [ -f .env ]; then \
		echo "${YELLOW}  .env is a regular file (not a symlink)${RESET}"; \
	else \
		echo "${YELLOW}  .env does not exist${RESET}"; \
	fi
	@echo ""
	@if [ -n "$(DB_URL)" ]; then \
		echo "  DB_URL: Set ✓"; \
	else \
		echo "  DB_URL: ${YELLOW}Not set ✗${RESET}"; \
	fi
