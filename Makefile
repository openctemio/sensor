# =============================================================================
# OpenCTEM Sensor Makefile
# =============================================================================

.PHONY: all build test lint clean docker docker-slim docker-ci docker-push help \
        pre-commit-install pre-commit-run security-scan fmt \
        release release-snapshot release-check

# Variables
# Dev builds: "<highest vX.Y.Z tag>-dev+<short sha>" (openctemio/openctem
# RFC-037): the highest tag by version sort, never `git describe`, whose answer
# depends on which tags happen to be ancestors. Releases come from tags
# (GoReleaser, docker-publish.yml), not from this Makefile.
VERSION ?= $(shell v=$$(git tag -l 'v*' 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | sort -V | tail -n 1); \
	c=$$(git rev-parse --short=8 HEAD 2>/dev/null); \
	if [ -n "$$c" ]; then echo "$${v:-v0.0.0}-dev+$$c"; else echo dev; fi)
# Docker tags cannot carry "+".
IMAGE_TAG ?= $(subst +,-,$(VERSION))
REGISTRY ?= docker.io
IMAGE_NAME ?= openctemio/sensor
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
BINARY := openctemio-sensor

# Default target
all: lint test build

# =============================================================================
# Build
# =============================================================================

build: ## Build the sensor binary
	@echo "Building sensor..."
	@mkdir -p bin
	go build -ldflags="-w -s -X main.Version=$(VERSION)" -o bin/$(BINARY) .
	@echo "Built: bin/$(BINARY)"

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X main.Version=$(VERSION)" -o bin/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-w -s -X main.Version=$(VERSION)" -o bin/$(BINARY)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s -X main.Version=$(VERSION)" -o bin/$(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s -X main.Version=$(VERSION)" -o bin/$(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags="-w -s -X main.Version=$(VERSION)" -o bin/$(BINARY)-windows-amd64.exe .
	@echo "Built binaries in bin/"

install: build ## Install to /usr/local/bin
	@echo "Installing sensor..."
	sudo cp bin/$(BINARY) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY)"

# =============================================================================
# Test
# =============================================================================

test: ## Run tests
	go test -v -race ./...

test-coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# =============================================================================
# Lint & Format
# =============================================================================

lint: ## Run linters
	@echo "Running golangci-lint..."
	@golangci-lint run ./...

fmt: ## Format code
	go fmt ./...
	gofmt -s -w $(GO_FILES)

# =============================================================================
# Security & Pre-commit
# =============================================================================

pre-commit-install: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		echo "pre-commit already installed"; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Installing via brew..."; \
		brew install pre-commit; \
	elif command -v pipx >/dev/null 2>&1; then \
		echo "Installing via pipx..."; \
		pipx install pre-commit; \
	else \
		echo "Please install pre-commit: brew install pre-commit"; \
		exit 1; \
	fi
	@pre-commit install
	@echo "Pre-commit hooks installed!"

pre-commit-run: ## Run all pre-commit hooks
	@pre-commit run --all-files

security-scan: ## Run full security scan
	@echo "Running full security scan..."
	@echo ""
	@echo "=== Betterleaks (Secret Detection) ==="
	@betterleaks git . --redact --verbose || true
	@echo ""
	@echo "=== Golangci-lint with Gosec (Code Security) ==="
	@golangci-lint run ./... || true
	@echo ""
	@echo "=== Trivy (Vulnerability Scan) ==="
	@trivy fs --severity HIGH,CRITICAL --scanners vuln,secret . || true
	@echo ""
	@echo "Security scan complete!"

# =============================================================================
# Release (GoReleaser)
# =============================================================================

release-check: ## Validate GoReleaser config
	@echo "Validating GoReleaser config..."
	@goreleaser check
	@echo "Config is valid!"

release-snapshot: ## Build release artifacts locally (no publish)
	@echo "Building snapshot release..."
	@goreleaser release --snapshot --clean
	@echo "Artifacts in dist/"

release: ## Build and publish release (requires git tag)
	@echo "Building release..."
	@goreleaser release --clean

# =============================================================================
# Docker
# =============================================================================

docker: docker-full ## Build full Docker image (alias)

docker-full: ## Build full Docker image
	docker build --target full --build-arg VERSION=$(VERSION) -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) -t $(REGISTRY)/$(IMAGE_NAME):latest .

docker-slim: ## Build slim Docker image
	docker build --target slim --build-arg VERSION=$(VERSION) -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)-slim -t $(REGISTRY)/$(IMAGE_NAME):slim .

docker-ci: ## Build CI Docker image
	docker build --target ci --build-arg VERSION=$(VERSION) -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)-ci -t $(REGISTRY)/$(IMAGE_NAME):ci .

docker-all: docker-full docker-slim docker-ci ## Build all Docker images

docker-push: ## Push all Docker images
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):latest
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)-slim
	docker push $(REGISTRY)/$(IMAGE_NAME):slim
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)-ci
	docker push $(REGISTRY)/$(IMAGE_NAME):ci

# =============================================================================
# Run
# =============================================================================

run: build ## Run the sensor (example)
	./bin/$(BINARY) --help

run-scan: build ## Run a scan on current directory
	./bin/$(BINARY) scan --target . --verbose

# =============================================================================
# Clean
# =============================================================================

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f $(BINARY)
	go clean -cache

# =============================================================================
# Development
# =============================================================================

dev-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

mod-tidy: ## Tidy go modules
	go mod tidy

# =============================================================================
# Help
# =============================================================================

help: ## Show this help
	@echo "OpenCTEM Sensor - Make targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build            # Build the sensor"
	@echo "  make build-all        # Build for all platforms"
	@echo "  make docker           # Build Docker image"
	@echo "  make test             # Run tests"
	@echo "  make security-scan    # Run security scan"
	@echo "  make release-snapshot # Build release locally (no publish)"
	@echo "  make release-check    # Validate GoReleaser config"
