# Makefile for authpf-api
# Supports building for FreeBSD and OpenBSD on amd64, arm64, armv7, and riscv64

.PHONY: help build test clean lint fmt vet coverage build-all build-freebsd build-openbsd

# Variables
APP_NAME := authpf-api
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR := ./build
DIST_DIR := ./dist
GO := go
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Supported OS and architectures
SUPPORTED_OS := freebsd openbsd
SUPPORTED_ARCH := amd64 arm64 armv7 riscv64

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

# Default target - show help
help:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║                    authpf-api Build System                     ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "  make help              Show this help message"
	@echo "  make build             Build for current OS/ARCH"
	@echo "  make build-all         Build for all supported OS/ARCH combinations"
	@echo "  make build-freebsd     Build for all FreeBSD architectures"
	@echo "  make build-openbsd     Build for all OpenBSD architectures"
	@echo ""
	@echo "  make test              Run all tests"
	@echo "  make test-verbose      Run tests with verbose output"
	@echo "  make coverage          Run tests with coverage report"
	@echo "  make coverage-html     Generate HTML coverage report"
	@echo ""
	@echo "  make lint              Run linter (golangci-lint)"
	@echo "  make fmt               Format code (gofmt)"
	@echo "  make vet               Run go vet"
	@echo ""
	@echo "  make clean             Remove build artifacts"
	@echo "  make clean-all         Remove all build and dist artifacts"
	@echo ""
	@echo "Supported OS: $(SUPPORTED_OS)"
	@echo "Supported ARCH: $(SUPPORTED_ARCH)"
	@echo ""
	@echo "Examples:"
	@echo "  make build                          # Build for current system"
	@echo "  make build GOOS=freebsd GOARCH=amd64"
	@echo "  make build-all                      # Build all combinations"
	@echo "  make test                           # Run tests"
	@echo "  make coverage                       # Generate coverage report"
	@echo ""

# Build for current OS/ARCH
build: clean
	@echo "Building $(APP_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-$(GOOS)-$(GOARCH) .
	@echo "✓ Build complete: $(BUILD_DIR)/$(APP_NAME)-$(GOOS)-$(GOARCH)"

# Build for all supported OS/ARCH combinations
build-all: clean
	@echo "Building $(APP_NAME) for all supported platforms..."
	@mkdir -p $(DIST_DIR)
	@for os in $(SUPPORTED_OS); do \
		for arch in $(SUPPORTED_ARCH); do \
			echo "  Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-$$os-$$arch . || exit 1; \
		done; \
	done
	@echo "✓ All builds complete in $(DIST_DIR)/"
	@ls -lh $(DIST_DIR)/

# Build for all FreeBSD architectures
build-freebsd: clean
	@echo "Building $(APP_NAME) for FreeBSD..."
	@mkdir -p $(DIST_DIR)
	@for arch in $(SUPPORTED_ARCH); do \
		echo "  Building freebsd/$$arch..."; \
		GOOS=freebsd GOARCH=$$arch $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-freebsd-$$arch . || exit 1; \
	done
	@echo "✓ FreeBSD builds complete in $(DIST_DIR)/"
	@ls -lh $(DIST_DIR)/$(APP_NAME)-freebsd-*

# Build for all OpenBSD architectures
build-openbsd: clean
	@echo "Building $(APP_NAME) for OpenBSD..."
	@mkdir -p $(DIST_DIR)
	@for arch in $(SUPPORTED_ARCH); do \
		echo "  Building openbsd/$$arch..."; \
		GOOS=openbsd GOARCH=$$arch $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-openbsd-$$arch . || exit 1; \
	done
	@echo "✓ OpenBSD builds complete in $(DIST_DIR)/"
	@ls -lh $(DIST_DIR)/$(APP_NAME)-openbsd-*

# Run all tests
test:
	@echo "Running tests..."
	@$(GO) test -v ./...
	@echo "✓ Tests passed"

# Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	@$(GO) test -v -race -count=1 ./...
	@echo "✓ Tests passed"

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	@$(GO) test -v -race -covermode=atomic -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out
	@echo "✓ Coverage report generated: coverage.out"

# Generate HTML coverage report
coverage-html: coverage
	@echo "Generating HTML coverage report..."
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ HTML coverage report generated: coverage.html"

# Format code
fmt:
	@echo "Formatting code..."
	@$(GO) fmt ./...
	@echo "✓ Code formatted"

# Run go vet
vet:
	@echo "Running go vet..."
	@$(GO) vet ./...
	@echo "✓ Go vet passed"

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	@golangci-lint run ./...
	@echo "✓ Linter passed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Build directory cleaned"

# Clean all artifacts
clean-all: clean
	@echo "Cleaning all artifacts..."
	@rm -rf $(DIST_DIR)
	@rm -f coverage.out coverage.html
	@echo "✓ All artifacts cleaned"

# Development setup
setup:
	@echo "Setting up development environment..."
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "✓ Development environment ready"

# Run the application (for current system)
run: build
	@echo "Running $(APP_NAME)..."
	@./$(BUILD_DIR)/$(APP_NAME)-$(GOOS)-$(GOARCH) -foreground

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "✓ Dependencies installed"

# Show build info
info:
	@echo "Build Information:"
	@echo "  App Name: $(APP_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Current OS: $(GOOS)"
	@echo "  Current ARCH: $(GOARCH)"
	@echo "  Go Version: $(shell $(GO) version)"
	@echo "  Build Dir: $(BUILD_DIR)"
	@echo "  Dist Dir: $(DIST_DIR)"
