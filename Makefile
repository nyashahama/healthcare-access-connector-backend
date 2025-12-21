.PHONY: help build run test clean migrate-up migrate-down migrate-create sqlc docker-build docker-up docker-down lint fmt tidy generate-jwt dev test-integration

# Variables
APP_NAME=healthcare-access-connector-backend

BINARY_NAME=api
MAIN_PATH=./cmd/api
DOCKER_IMAGE=$(APP_NAME):latest
DB_URL?=postgres://postgres:admin@localhost:5432/dbname?sslmode=disable

# Colors for output
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RESET  := $(shell tput -Txterm sgr0)

help: ## Show this help
	@echo '${GREEN}Available targets:${RESET}'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${YELLOW}%-20s${RESET} %s\n", $$1, $$2}'

## Development

dev: ## Run application in development mode with hot reload
	air -c .air.toml

build: ## Build the application binary
	@echo "${GREEN}Building $(BINARY_NAME)...${RESET}"
	CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/$(BINARY_NAME) $(MAIN_PATH)/main.go
	@echo "${GREEN}Build complete: bin/$(BINARY_NAME)${RESET}"

run: ## Run the application
	@echo "${GREEN}Running application...${RESET}"
	go run $(MAIN_PATH)/main.go

install-tools: ## Install development tools
	@echo "${GREEN}Installing tools...${RESET}"
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/cosmtrek/air@latest

## Testing

test: ## Run tests with coverage
	@echo "${GREEN}Running tests...${RESET}"
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "${GREEN}Generating coverage report...${RESET}"
	go tool cover -html=coverage.out -o coverage.html
	@echo "${GREEN}Coverage report: coverage.html${RESET}"

test-integration: ## Run integration tests
	@echo "${GREEN}Running integration tests...${RESET}"
	go test -v -tags=integration ./tests/integration/...

test-unit: ## Run only unit tests
	@echo "${GREEN}Running unit tests...${RESET}"
	go test -v -short ./...

bench: ## Run benchmarks
	@echo "${GREEN}Running benchmarks...${RESET}"
	go test -bench=. -benchmem ./...

## Database

migrate-create: ## Create a new migration (usage: make migrate-create name=add_users_table)
	@if [ -z "$(name)" ]; then echo "Error: name is required. Usage: make migrate-create name=migration_name"; exit 1; fi
	@echo "${GREEN}Creating migration: $(name)${RESET}"
	migrate create -ext sql -dir migrations -seq $(name)

migrate-up: ## Run database migrations up
	@echo "${GREEN}Running migrations up...${RESET}"
	migrate -path migrations -database "$(DB_URL)" up

migrate-down: ## Run database migrations down
	@echo "${YELLOW}Warning: This will rollback the last migration${RESET}"
	migrate -path migrations -database "$(DB_URL)" down 1

migrate-force: ## Force migration version (usage: make migrate-force version=1)
	@if [ -z "$(version)" ]; then echo "Error: version is required"; exit 1; fi
	migrate -path migrations -database "$(DB_URL)" force $(version)

migrate-status: ## Show migration status
	migrate -path migrations -database "$(DB_URL)" version

sqlc: ## Generate sqlc code
	@echo "${GREEN}Generating sqlc code...${RESET}"
	sqlc generate

## Docker

docker-build: ## Build Docker image
	@echo "${GREEN}Building Docker image...${RESET}"
	docker build -t $(DOCKER_IMAGE) .

docker-up: ## Start all services with Docker Compose
	@echo "${GREEN}Starting services...${RESET}"
	docker-compose up -d
	@echo "${GREEN}Services started. API available at http://localhost:8080${RESET}"

docker-up-monitoring: ## Start services with monitoring stack
	@echo "${GREEN}Starting services with monitoring...${RESET}"
	docker-compose --profile monitoring up -d
	@echo "${GREEN}Services started.${RESET}"
	@echo "${GREEN}API: http://localhost:8080${RESET}"
	@echo "${GREEN}Prometheus: http://localhost:9090${RESET}"
	@echo "${GREEN}Grafana: http://localhost:3000 (admin/admin)${RESET}"

docker-down: ## Stop all services
	@echo "${YELLOW}Stopping services...${RESET}"
	docker-compose down

docker-down-volumes: ## Stop services and remove volumes
	@echo "${YELLOW}Warning: This will delete all data${RESET}"
	docker-compose down -v

docker-logs: ## View Docker logs
	docker-compose logs -f

docker-logs-api: ## View API logs only
	docker-compose logs -f api

docker-ps: ## Show running containers
	docker-compose ps

docker-exec: ## Execute command in API container (usage: make docker-exec cmd="ls -la")
	docker-compose exec api $(cmd)

docker-shell: ## Open shell in API container
	docker-compose exec api sh

docker-rebuild: ## Force rebuild Docker image without cache
	@echo "${YELLOW}Removing old images...${RESET}"
	docker-compose down
	docker-compose rm -f api || true
	docker rmi $(APP_NAME)-api || true
	docker rmi $(DOCKER_IMAGE) || true
	@echo "${GREEN}Building fresh image (no cache)...${RESET}"
	docker-compose build --no-cache api
	@echo "${GREEN}Starting services...${RESET}"
	docker-compose up -d
	@echo "${GREEN}Waiting for services to start...${RESET}"
	sleep 5
	@echo "${GREEN}Testing health endpoint...${RESET}"
	curl http://localhost:8080/health || echo "Health check failed"

docker-clean: ## Clean all Docker resources for this project
	@echo "${YELLOW}Warning: This will remove all containers, images, and volumes${RESET}"
	docker-compose down -v --remove-orphans
	docker-compose rm -f
	docker rmi $(APP_NAME)-api || true
	docker rmi $(DOCKER_IMAGE) || true
	docker volume prune -f
	@echo "${GREEN}Cleaned!${RESET}"

docker-verify: ## Verify Docker is running the correct code
	@echo "${GREEN}Checking what version is running...${RESET}"
	@echo "1. Health check:"
	@curl -s http://localhost:8080/health | jq . || echo "Failed"
	@echo "\n2. Container logs (last 20 lines):"
	@docker-compose logs --tail=20 api
	@echo "\n3. Binary info inside container:"
	@docker-compose exec api ls -lh /home/appuser/api
	@echo "\n4. Container created time:"
	@docker-compose ps api

## Code Quality

lint: ## Run linter
	@echo "${GREEN}Running linter...${RESET}"
	golangci-lint run --timeout 5m

fmt: ## Format code
	@echo "${GREEN}Formatting code...${RESET}"
	go fmt ./...
	gofumpt -l -w .

vet: ## Run go vet
	@echo "${GREEN}Running go vet...${RESET}"
	go vet ./...

tidy: ## Tidy dependencies
	@echo "${GREEN}Tidying dependencies...${RESET}"
	go mod tidy
	go mod verify

## Security

security-scan: ## Run security scan
	@echo "${GREEN}Running security scan...${RESET}"
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

## Utilities

generate-jwt: ## Generate a secure JWT secret
	@echo "${GREEN}Generated JWT Secret (copy to .env):${RESET}"
	@openssl rand -base64 32

clean: ## Clean build artifacts
	@echo "${YELLOW}Cleaning...${RESET}"
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -rf tmp/

check: lint vet test ## Run all checks (lint, vet, test)

ci: tidy fmt lint vet test ## Run CI pipeline locally

setup: install-tools ## Initial project setup
	@echo "${GREEN}Setting up project...${RESET}"
	cp .env.example .env
	@echo "${YELLOW}Please edit .env and set JWT_SECRET${RESET}"
	@echo "${GREEN}Run 'make docker-up' to start services${RESET}"

## API Testing

api-register: ## Test registration endpoint
	curl -X POST http://localhost:8080/api/v1/register \
		-H "Content-Type: application/json" \
		-d '{"username":"testuser","email":"test@example.com","password":"password123","role":"user"}'

api-login: ## Test login endpoint
	curl -X POST http://localhost:8080/api/v1/login \
		-H "Content-Type: application/json" \
		-d '{"email":"test@example.com","password":"password123"}'

api-health: ## Test health endpoint
	curl http://localhost:8080/health

api-metrics: ## View Prometheus metrics
	curl http://localhost:8080/metrics

## Default

.DEFAULT_GOAL := help
