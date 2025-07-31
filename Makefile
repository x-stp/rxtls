# Makefile for rxtls

# Variables
BINARY_NAME := rxtls
MAIN_PATH := ./cmd/rxtls
BUILD_DIR := ./dist
COVERAGE_FILE := coverage.out

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOVET := $(GOCMD) vet

# Build flags
LDFLAGS := -s -w
BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

# Linting
GOLANGCI_LINT_VERSION := v1.54.2
GOLANGCI_LINT := $(shell which golangci-lint 2> /dev/null)

.PHONY: all build clean test lint lint-install lint-fix security fmt vet tidy help

# Default target
all: lint test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@$(GOBUILD) $(BUILD_FLAGS) -o $(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete: ./$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm -rf $(BUILD_DIR)
	@rm -f $(COVERAGE_FILE)
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@$(GOTEST) -v -race -cover ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Install golangci-lint if not present
lint-install:
ifndef GOLANGCI_LINT
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)
else
	@echo "golangci-lint is already installed at $(GOLANGCI_LINT)"
endif

# Run linters
lint: lint-install
	@echo "Running linters..."
	@golangci-lint run --timeout=5m ./...

# Run linters and fix issues where possible
lint-fix: lint-install
	@echo "Running linters with auto-fix..."
	@golangci-lint run --fix --timeout=5m ./...

# Run security-focused linters only
security: lint-install
	@echo "Running security checks..."
	@golangci-lint run --disable-all --enable=gosec,exportloopref,bodyclose --timeout=5m ./...

# Run gosec directly with more detailed output
gosec:
	@echo "Running gosec security scanner..."
	@gosec -fmt=json -out=gosec-report.json -stdout -verbose=text -severity=medium ./... || true
	@echo "Security report saved to gosec-report.json"

# Format code
fmt:
	@echo "Formatting code..."
	@$(GOFMT) -s -w .
	@$(GOCMD) fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	@$(GOVET) ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	@$(GOMOD) tidy
	@$(GOMOD) verify

# Quick check - format, vet, and lint
check: fmt vet lint

# CI/CD oriented target - strict checking
ci: tidy fmt vet lint test

# Install all development dependencies
dev-deps: lint-install
	@echo "Installing development dependencies..."
	@$(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest
	@echo "Development dependencies installed"

# Show help
help:
	@echo "Available targets:"
	@echo "  make build         - Build the binary"
	@echo "  make test          - Run tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make lint          - Run all linters"
	@echo "  make lint-fix      - Run linters with auto-fix"
	@echo "  make security      - Run security-focused linters"
	@echo "  make gosec         - Run gosec security scanner"
	@echo "  make fmt           - Format code"
	@echo "  make vet           - Run go vet"
	@echo "  make tidy          - Tidy go modules"
	@echo "  make check         - Quick check (fmt, vet, lint)"
	@echo "  make ci            - Full CI check"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make dev-deps      - Install development dependencies"
	@echo "  make help          - Show this help message"