.PHONY: help dev prod docker-up docker-down docker-logs db-migrate db-seed test clean build run

# Variables
APP_NAME=healthcare-access-connector-backend
BINARY_NAME=api
MAIN_PATH=./cmd/api
DOCKER_IMAGE=$(APP_NAME):latest
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

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
	@echo "  make db-migrate       - Run database migrations"
	@echo "  make db-seed          - Seed database with test data"
	@echo "  make migrate-up       - Run migrations (alias)"
	@echo "  make migrate-down     - Rollback last migration"
	@echo "  make migrate-create   - Create new migration (name=migration_name)"
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
	@echo "  make sqlc             - Generate database code"
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

# Database migrations
db-migrate:
	@echo "${GREEN}Running database migrations...${RESET}"
	migrate -path database/migrations -database "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable" up

migrate-up: db-migrate

migrate-down:
	@echo "${YELLOW}Warning: This will rollback the last migration${RESET}"
	migrate -path database/migrations -database "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable" down 1

migrate-create:
	@if [ -z "$(name)" ]; then echo "${YELLOW}Error: name is required. Usage: make migrate-create name=migration_name${RESET}"; exit 1; fi
	@echo "${GREEN}Creating migration: $(name)${RESET}"
	migrate create -ext sql -dir database/migrations -seq $(name)

# Seed database with test data
db-seed:
	@echo "${GREEN}Seeding database with test data...${RESET}"
	go run cmd/seed/main.go

# Generate sqlc code
sqlc:
	@echo "${GREEN}Generating sqlc code...${RESET}"
	sqlc generate

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
	@echo "${GREEN}✓ Tools installed!${RESET}"

# Generate JWT secret
generate-jwt:
	@echo "${GREEN}Generated JWT Secret (copy to .env):${RESET}"
	@openssl rand -base64 32

# Run all checks
check: lint vet test
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
	@if [ -L .env ]; then \
		target=$(readlink .env); \
		echo "  .env is a symlink pointing to: $target"; \
		if [ "$target" = ".env.development" ]; then \
			echo "${GREEN}  → DEVELOPMENT mode${RESET}"; \
		elif [ "$target" = ".env.production" ]; then \
			echo "${YELLOW}  → PRODUCTION mode${RESET}"; \
		fi; \
	elif [ -f .env ]; then \
		echo "${YELLOW}  .env is a regular file (not a symlink)${RESET}"; \
	else \
		echo "${YELLOW}  .env does not exist${RESET}"; \
	fi

switch-dev:
	@echo "${GREEN}Switching to DEVELOPMENT environment...${RESET}"
	@rm -f .env
	@ln -sf .env.development .env
	@echo "${GREEN}✓ Now using .env.development${RESET}"
	@echo "Run 'make dev' to start in development mode"

switch-prod:
	@echo "${YELLOW}Switching to PRODUCTION environment...${RESET}"
	@rm -f .env
	@ln -sf .env.production .env
	@echo "${YELLOW}✓ Now using .env.production${RESET}"
	@echo "Run 'make prod' to start in production mode"
