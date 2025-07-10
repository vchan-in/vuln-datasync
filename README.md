# Vulnerability Data Synchronization System (vuln-datasync)

A high-performance, independent vulnerability aggregation system that merges, deduplicates, and synchronizes vulnerability data from multiple sources into a master PostgreSQL database.

## Overview

Based on learnings from the ossdeps POC, this system implements a robust vulnerability data pipeline that:

- **Fetches** vulnerability data from multiple sources (OSV via GCS/HTTP, GitLab, CVE Project)
- **Merges** data with intelligent priority-based rules (OSV > GitLab > CVE)
- **Deduplicates** using alias-based matching and data hash verification
- **Ingests** processed data into PostgreSQL with optimized batch operations
- **Exports** versioned snapshots for downstream consumption

## Architecture

```
┌─────────────────────────────────────────┐
│ Vulnerabilities (OSV, GitLab, CVE, ...) │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ vuln-datasync                          │
│ (Merge, Deduplicate, Ingest)           │
│ - GCS priority with HTTP fallback      │
│ - Priority-based merging               │
│ - Alias-based deduplication            │
│ - Data normalization                   │
│ - Batch processing                     │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ Master PostgreSQL Cluster              │
│ (Master Database)                      │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ Export PostgreSQL Snapshot             │
│ (versioned, compressed)                │
│ (daily/weekly schedule)                │
└─────────────────────────────────────────┘
```

## 🚀 Quick Start for Developers

### Prerequisites
- **Go 1.23+** - Programming language
- **PostgreSQL 14+** - Primary database
- **Redis 6+** - Job queue and caching
- **Docker & Docker Compose** - For local development
- **Git** - For GitLab source integration

### One-Command Setup
```bash
# Complete development environment setup
make dev-setup
```

This will:
- Install all development tools (migrate, sqlc, golangci-lint, gosec)
- Download Go dependencies
- Set up database with migrations
- Generate type-safe database code with sqlc
- Create .env file from template

### Manual Setup (Alternative)

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd vuln-datasync
   
   # Copy environment template
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Install Dependencies**
   ```bash
   make deps                 # Download Go modules
   make env-setup           # Install dev tools
   ```

3. **Database Setup**
   ```bash
   # Start database with Docker
   docker-compose up -d postgres redis
   
   # Run migrations
   make migrate
   
   # Generate database code
   make sqlc-generate
   ```

4. **Run Application**
   ```bash
   make run-dev             # Development mode
   # or
   make run                 # Production mode
   ```

## 🛠️ Development Workflow

### Daily Development Commands
```bash
# Quick development cycle
make quick-test             # Format, vet, and test
make run-dev               # Run in development mode

# Code quality
make fmt                   # Format code
make lint                  # Run linter
make security              # Security scan
make quality               # All quality checks

# Testing
make test                  # Unit tests
make test-integration      # Integration tests
make test-performance      # Performance benchmarks
make test-all             # All tests
```

### Database Operations
```bash
# Migrations
make migrate              # Apply all migrations
make migrate-down         # Rollback migrations
make migrate-force VERSION=1  # Force specific version

# Database management
make db-reset             # Reset database (DANGER)
make sqlc-generate        # Regenerate database code

# Monitoring
make status               # Show system status
```

### Docker Development
```bash
# Local services
make docker-run           # Start all services
make docker-stop          # Stop all services
make docker-logs          # View logs

# Build images
make docker-build         # Build application image
```

## 🏗️ Project Structure

```
vuln-datasync/
├── cmd/vuln-datasync/          # Application entry point
│   └── main.go
├── internal/                   # Private application code
│   ├── api/                   # HTTP API server
│   ├── config/                # Configuration management
│   ├── database/              # Database layer
│   │   └── generated/         # sqlc generated code
│   ├── fetchers/              # Data source fetchers
│   │   └── osv/              # OSV fetcher (GCS + HTTP)
│   ├── jobs/                  # Background job processing
│   ├── merger/                # Vulnerability merging logic
│   └── types/                 # Shared type definitions
├── migrations/                 # Database migrations
├── sql/                       # SQL queries for sqlc
│   ├── vulnerabilities.sql   # Vulnerability operations
│   └── jobs.sql              # Job queue operations
├── scripts/                   # Utility scripts
├── docker-compose.yml         # Local development services
├── Dockerfile                 # Application container
├── sqlc.yaml                  # Database code generation
└── Makefile                   # Build automation
```

## 🔧 Key Technologies

### Data Sources with Fallback Strategy
- **OSV (Open Source Vulnerabilities)**
  - Primary: GCS bucket `gs://osv-vulnerabilities/all.zip`
  - Fallback: HTTP `https://osv-vulnerabilities.storage.googleapis.com/all.zip`
  - Processing: 20-worker pool, memory-efficient streaming
- **GitLab**: Git repository cloning and YAML processing
- **CVE Project**: GitHub repository `https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip`

### Database & Performance
- **PostgreSQL**: Primary data store with optimized indexing
- **sqlc**: Type-safe SQL with code generation
- **Redis**: Job queue (Asynq) and caching
- **Batch Processing**: 1000-5000 record batches for optimal throughput

### Background Processing
- **Asynq**: Redis-based job queue with retry logic
- **Worker Pools**: Parallel processing (20-50 workers)
- **Graceful Shutdown**: Proper signal handling

## 📊 Performance Optimizations

Based on POC learnings:

### Memory Management
- Stream large ZIP files instead of loading into memory
- Worker pools for parallel processing
- Explicit garbage collection for long-running processes

### Caching Strategy
- **L1**: In-memory alias cache for deduplication
- **L2**: LRU cache for frequently accessed vulnerabilities
- **L3**: Redis cache for distributed systems

### Database Optimization
- GIN indexes for array and JSONB columns
- Connection pooling (100 max, 20 min connections)
- Batch upserts with `INSERT ON CONFLICT UPDATE`

## 🧪 Testing & Validation

### Quick Integration Test
```bash
# Run the built-in integration test
go run test_integration.go
```

### Manual Testing Steps

1. **Build and Basic Validation**
```bash
# Ensure code compiles correctly
go build ./...

# Format code
go fmt ./...

# Static analysis
go vet ./...

# Run integration test
go run test_integration.go
```

2. **Production Environment Test**
```bash
# Set up minimal environment
export DB_HOST=localhost
export DB_NAME=vulndb_test
export REDIS_ADDR=localhost:6379

# Run with help to verify CLI
go run cmd/vuln-datasync/main.go --help

# Start service (will fail gracefully without DB)
go run cmd/vuln-datasync/main.go
```

3. **End-to-End Testing** (with infrastructure)
```bash
# Start dependencies
docker-compose up -d postgres redis

# Run database migrations
make migrate-up

# Start the service
make run

# Trigger a sync job
curl -X POST http://localhost:8080/api/jobs/sync

# Check job status
curl http://localhost:8080/api/jobs/status
```

### Validation Checklist
- ✅ Code builds without errors
- ✅ All linting passes (no cognitive complexity issues)
- ✅ Integration test passes
- ✅ All fetchers implement the interface correctly
- ✅ Database schema is valid
- ✅ Job processing works end-to-end
- ✅ Configuration loading works
- ✅ API endpoints respond correctly
````
