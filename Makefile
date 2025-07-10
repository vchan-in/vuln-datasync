# Vulnerability Data Synchronization System (vuln-datasync) Makefile
# Production-ready build automation based on ossdeps POC learnings

.PHONY: help build build-prod run test test-integration test-performance test-all \
        clean deps mod-tidy migrate migrate-down migrate-up sqlc-generate docker-build \
        docker-run docker-stop lint fmt vet security-scan coverage install dev-setup \
        benchmark profile env-setup quality quick-test production-build ci cd

# Default target
.DEFAULT_GOAL := help

# Build configuration
BINARY_NAME := vuln-datasync
BINARY_PATH := ./cmd/vuln-datasync
BUILD_DIR := ./bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S_UTC')

# Go configuration
GO := go
GOFLAGS := -ldflags="-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"
GOFLAGS_PROD := -ldflags="-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME) -s -w"

# Docker configuration
DOCKER_IMAGE := vuln-datasync
DOCKER_TAG := $(VERSION)
DOCKER_REGISTRY := # Set your registry here

# Database configuration for development
DB_HOST := localhost
DB_PORT := 5432
DB_NAME := vulndb
DB_USER := postgres
DB_PASSWORD := password
DB_SSL_MODE := disable
DB_DSN := postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSL_MODE)

# Redis configuration
REDIS_ADDR := localhost:6379
REDIS_PASSWORD := 
REDIS_DB := 0

# Performance test configuration
PERF_WORKERS := 20
PERF_BATCH_SIZE := 1000

# Colors for terminal output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

##@ Help

help: ## Display this help
	@echo "$(BLUE)Vulnerability Data Synchronization System (vuln-datasync)$(RESET)"
	@echo "$(BLUE)Production-ready build automation based on ossdeps POC learnings$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make $(GREEN)<target>$(RESET)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

deps: ## Install dependencies
	@echo "$(BLUE)Installing Go dependencies...$(RESET)"
	$(GO) mod download
	$(GO) mod verify

mod-tidy: ## Tidy go modules
	@echo "$(BLUE)Tidying Go modules...$(RESET)"
	$(GO) mod tidy

env-setup: ## Set up development environment tools
	@echo "$(BLUE)Setting up development environment...$(RESET)"
	@if [ ! -f .env ]; then \
		cp .env.example .env 2>/dev/null || echo "# Create your .env file" > .env; \
		echo "$(YELLOW)Created .env file. Please edit with your configuration.$(RESET)"; \
	fi
	@echo "$(BLUE)Installing development tools...$(RESET)"
	@if ! command -v migrate >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing golang-migrate...$(RESET)"; \
		$(GO) install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest; \
	fi
	@if ! command -v sqlc >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing sqlc...$(RESET)"; \
		$(GO) install github.com/kyleconroy/sqlc/cmd/sqlc@latest; \
	fi
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing golangci-lint...$(RESET)"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell $(GO) env GOPATH)/bin; \
	fi
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing gosec...$(RESET)"; \
		$(GO) install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	fi
	@echo "$(GREEN)Development environment ready!$(RESET)"

dev-setup: env-setup deps migrate sqlc-generate ## Complete development setup
	@echo "$(GREEN)Development environment fully configured!$(RESET)"
	@echo "$(YELLOW)Next steps:$(RESET)"
	@echo "  1. Edit .env file with your configuration"
	@echo "  2. Start services: make docker-run"
	@echo "  3. Run application: make run-dev"

##@ Building

build: deps ## Build development binary
	@echo "$(BLUE)Building development binary...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)
	@echo "$(GREEN)Binary built: $(BUILD_DIR)/$(BINARY_NAME)$(RESET)"

build-prod: deps ## Build production binary (optimized)
	@echo "$(BLUE)Building production binary...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_PROD) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)
	@echo "$(GREEN)Production binary built: $(BUILD_DIR)/$(BINARY_NAME)$(RESET)"

build-all: ## Build binaries for multiple platforms
	@echo "$(BLUE)Building for multiple platforms...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	# Linux AMD64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS_PROD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BINARY_PATH)
	# Linux ARM64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS_PROD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(BINARY_PATH)
	# macOS AMD64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS_PROD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(BINARY_PATH)
	# macOS ARM64 (Apple Silicon)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS_PROD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(BINARY_PATH)
	# Windows AMD64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS_PROD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(BINARY_PATH)
	@echo "$(GREEN)Multi-platform binaries built in $(BUILD_DIR)/$(RESET)"

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf $(BUILD_DIR)
	$(GO) clean -cache
	@echo "$(GREEN)Build artifacts cleaned$(RESET)"

##@ Running

run: build ## Run the application (production mode)
	@echo "$(BLUE)Running vuln-datasync...$(RESET)"
	DB_DSN="$(DB_DSN)" \
	REDIS_ADDR="$(REDIS_ADDR)" \
	REDIS_PASSWORD="$(REDIS_PASSWORD)" \
	REDIS_DB="$(REDIS_DB)" \
	LOG_LEVEL="info" \
	$(BUILD_DIR)/$(BINARY_NAME)

run-dev: ## Run in development mode with hot reload
	@echo "$(BLUE)Running in development mode...$(RESET)"
	DB_DSN="$(DB_DSN)" \
	REDIS_ADDR="$(REDIS_ADDR)" \
	REDIS_PASSWORD="$(REDIS_PASSWORD)" \
	REDIS_DB="$(REDIS_DB)" \
	LOG_LEVEL="debug" \
	ENVIRONMENT="development" \
	$(GO) run $(BINARY_PATH)

##@ Database

migrate: ## Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path ./migrations -database "$(DB_DSN)" up; \
		echo "$(GREEN)Database migrations completed$(RESET)"; \
	else \
		echo "$(RED)migrate tool not found. Install with: make env-setup$(RESET)"; \
		exit 1; \
	fi

migrate-down: ## Rollback database migrations
	@echo "$(YELLOW)Rolling back database migrations...$(RESET)"
	migrate -path ./migrations -database "$(DB_DSN)" down
	@echo "$(GREEN)Database migrations rolled back$(RESET)"

migrate-up: ## Apply specific number of migrations (make migrate-up N=1)
	@echo "$(BLUE)Applying $(N) migration(s)...$(RESET)"
	migrate -path ./migrations -database "$(DB_DSN)" up $(N)

migrate-create: ## Create a new migration (make migrate-create NAME=add_index)
	@echo "$(BLUE)Creating migration: $(NAME)$(RESET)"
	migrate create -ext sql -dir ./migrations $(NAME)

migrate-version: ## Show current migration version
	migrate -path ./migrations -database "$(DB_DSN)" version

migrate-force: ## Force migration version (make migrate-force VERSION=1)
	@echo "$(YELLOW)Forcing migration version to $(VERSION)$(RESET)"
	migrate -path ./migrations -database "$(DB_DSN)" force $(VERSION)

sqlc-generate: ## Generate sqlc code from SQL files
	@echo "$(BLUE)Generating sqlc code...$(RESET)"
	@if command -v sqlc >/dev/null 2>&1; then \
		sqlc generate; \
		echo "$(GREEN)sqlc code generated$(RESET)"; \
	else \
		echo "$(RED)sqlc not found. Install with: make env-setup$(RESET)"; \
		exit 1; \
	fi

db-reset: migrate-down migrate ## Reset database (DANGER: drops all data)
	@echo "$(RED)Database reset completed$(RESET)"

##@ Testing

test: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(RESET)"
	$(GO) test -v -race -timeout=30s ./...

test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(RESET)"
	$(GO) test -v -race -timeout=300s -tags=integration ./...

test-performance: ## Run performance tests
	@echo "$(BLUE)Running performance tests...$(RESET)"
	$(GO) test -v -timeout=1800s -tags=performance ./... \
		-osv-workers=$(PERF_WORKERS) \
		-batch-size=$(PERF_BATCH_SIZE)

test-all: test test-integration test-performance ## Run all tests

benchmark: ## Run benchmarks
	@echo "$(BLUE)Running benchmarks...$(RESET)"
	$(GO) test -v -run=^$$ -bench=. -benchtime=10s -benchmem ./...

coverage: ## Generate test coverage report
	@echo "$(BLUE)Generating test coverage report...$(RESET)"
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(RESET)"

##@ Code Quality

fmt: ## Format Go code
	@echo "$(BLUE)Formatting Go code...$(RESET)"
	$(GO) fmt ./...

vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(RESET)"
	$(GO) vet ./...

lint: ## Run golangci-lint
	@echo "$(BLUE)Running golangci-lint...$(RESET)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(RED)golangci-lint not found. Install with: make env-setup$(RESET)"; \
		exit 1; \
	fi

security-scan: ## Run security scan with gosec
	@echo "$(BLUE)Running security scan...$(RESET)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "$(RED)gosec not found. Install with: make env-setup$(RESET)"; \
		exit 1; \
	fi

quality: fmt vet lint security-scan ## Run all code quality checks

##@ Docker

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(RESET)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(RESET)"

docker-run: ## Start services with docker-compose
	@echo "$(BLUE)Starting services with docker-compose...$(RESET)"
	docker-compose up -d

docker-stop: ## Stop services with docker-compose
	@echo "$(BLUE)Stopping services with docker-compose...$(RESET)"
	docker-compose down

docker-logs: ## View docker-compose logs
	docker-compose logs -f

docker-push: ## Push Docker image to registry
	@echo "$(BLUE)Pushing Docker image to registry...$(RESET)"
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "$(RED)Error: DOCKER_REGISTRY not set$(RESET)"; \
		exit 1; \
	fi
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)

##@ Production

production-build: clean quality test-all build-prod docker-build ## Full production build pipeline
	@echo "$(GREEN)Production build completed successfully!$(RESET)"

install: build-prod ## Install binary to system
	@echo "$(BLUE)Installing binary to /usr/local/bin...$(RESET)"
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)Binary installed to /usr/local/bin/$(BINARY_NAME)$(RESET)"

deploy-prod: production-build ## Prepare production deployment
	@echo "$(BLUE)Production deployment ready$(RESET)"
	@echo "$(YELLOW)Next steps:$(RESET)"
	@echo "  1. Deploy binary: make install"
	@echo "  2. Or use Docker: make docker-push && make docker-run"

##@ Monitoring & Maintenance

health-check: ## Check system health
	@echo "$(BLUE)Checking system health...$(RESET)"
	@curl -f http://localhost:8080/health 2>/dev/null || echo "$(RED)Health check failed$(RESET)"

metrics: ## View system metrics
	@echo "$(BLUE)Fetching system metrics...$(RESET)"
	@curl -s http://localhost:8080/metrics 2>/dev/null || echo "$(RED)Metrics unavailable$(RESET)"

status: ## Show system status
	@echo "$(BLUE)System Status:$(RESET)"
	@echo "  Database: $(DB_DSN)"
	@echo "  Redis: $(REDIS_ADDR)"
	@echo "  Version: $(VERSION)"
	@echo "  Commit: $(COMMIT)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo ""
	@echo "$(BLUE)Service Status:$(RESET)"
	@if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vuln-datasync 2>/dev/null; then \
		echo "  $(GREEN)✓ Service is running$(RESET)"; \
	else \
		echo "  $(YELLOW)○ Service not running or not installed$(RESET)"; \
	fi
	@echo ""
	@echo "$(BLUE)Database Connection:$(RESET)"
	@if command -v psql >/dev/null 2>&1; then \
		psql "$(DB_DSN)" -c "SELECT version();" 2>/dev/null | head -1 || echo "  $(RED)✗ Cannot connect to database$(RESET)"; \
	else \
		echo "  $(YELLOW)○ psql not available$(RESET)"; \
	fi

logs: ## View application logs
	@echo "$(BLUE)Application logs:$(RESET)"
	@if command -v journalctl >/dev/null 2>&1; then \
		journalctl -u vuln-datasync -n 50 --no-pager; \
	else \
		echo "$(YELLOW)journalctl not available. Use 'make docker-logs' for Docker logs$(RESET)"; \
	fi

##@ Quick Commands

quick-start: dev-setup docker-run ## Quick start for development (full setup)
	@echo "$(GREEN)Quick start completed! Run 'make run-dev' to start the application$(RESET)"

quick-test: fmt vet test ## Quick development test cycle
	@echo "$(GREEN)Quick test cycle completed$(RESET)"

ci: deps fmt vet lint test ## Continuous integration pipeline
	@echo "$(GREEN)CI pipeline completed$(RESET)"

cd: ci build-prod docker-build ## Continuous deployment pipeline
	@echo "$(GREEN)CD pipeline completed$(RESET)"

# Development workflow targets
dev: clean build run-dev ## Clean, build and run for development
all: clean deps quality test-all build-prod docker-build ## Complete build pipeline

# Show current configuration
show-config: ## Show current build configuration
	@echo "$(BLUE)Build Configuration:$(RESET)"
	@echo "  Binary Name: $(BINARY_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Commit: $(COMMIT)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Go Version: $(shell $(GO) version)"
	@echo "  Docker Tag: $(DOCKER_TAG)"
	@echo ""
	@echo "$(BLUE)Database Configuration:$(RESET)"
	@echo "  Host: $(DB_HOST):$(DB_PORT)"
	@echo "  Database: $(DB_NAME)"
	@echo "  User: $(DB_USER)"
	@echo ""
	@echo "$(BLUE)Performance Configuration:$(RESET)"
	@echo "  OSV Workers: $(PERF_WORKERS)"
	@echo "  Batch Size: $(PERF_BATCH_SIZE)"
