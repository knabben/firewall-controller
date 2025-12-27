# Makefile for firewall-controller (NetworkPolicy Agent)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=networkpolicy-agent
EXAMPLE_BINARY=apply-acl

# Build flags for Windows
WINDOWS_BUILD_FLAGS=GOOS=windows GOARCH=amd64

.PHONY: all build test clean deps tidy help

## help: Show this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## all: Run tests and build
all: test build

## build: Build the Windows binary
build:
	@echo "Building Windows binary..."
	$(WINDOWS_BUILD_FLAGS) $(GOBUILD) -o bin/$(BINARY_NAME).exe ./cmd/

## build-example: Build the example binary for manual testing
build-example:
	@echo "Building example binary for Windows..."
	$(WINDOWS_BUILD_FLAGS) $(GOBUILD) -o examples/apply-acl/$(EXAMPLE_BINARY).exe ./examples/apply-acl/

## test: Run tests (requires Windows or skip)
test:
	@echo "Running tests..."
	@echo "Note: Tests require Windows OS. Skipping on non-Windows platforms."
	@if [ "$$(uname -s)" = "Windows_NT" ] || [ "$$(uname -o 2>/dev/null)" = "Msys" ]; then \
		$(GOTEST) -v ./internal/hcn/...; \
	else \
		echo "Skipping tests on non-Windows platform"; \
	fi

## test-windows: Run tests on Windows (force)
test-windows:
	$(GOTEST) -v ./internal/hcn/...

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f bin/$(BINARY_NAME).exe
	rm -f examples/apply-acl/$(EXAMPLE_BINARY).exe

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOGET) -v ./...

## tidy: Tidy go.mod
tidy:
	@echo "Tidying go.mod..."
	$(GOMOD) tidy

## verify: Verify dependencies
verify:
	@echo "Verifying dependencies..."
	$(GOMOD) verify

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

## lint: Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install it from https://golangci-lint.run/"; \
	fi

## check: Run format, vet, and tests
check: fmt vet test

.DEFAULT_GOAL := help
