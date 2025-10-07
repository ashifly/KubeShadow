# KubeShadow Makefile
# Automatically handles CGO issues and builds for different environments

.PHONY: build build-no-cgo clean install deps test help

# Default target
all: build

# Build with automatic CGO detection and fallback
build:
	@echo "🔨 Building KubeShadow..."
	@echo "📦 Checking dependencies..."
	@go mod tidy
	@echo "🧹 Cleaning previous builds..."
	@go clean -cache
	@echo "🔧 Attempting build with CGO..."
	@if go build -o kubeshadow . 2>/dev/null; then \
		echo "✅ Build successful with CGO"; \
	else \
		echo "⚠️  CGO build failed, trying without CGO..."; \
		CGO_ENABLED=0 go build -o kubeshadow .; \
		echo "✅ Build successful without CGO"; \
	fi
	@chmod +x kubeshadow
	@echo "🎉 KubeShadow built successfully!"
	@echo "💡 Run './kubeshadow help' to get started"

# Build without CGO (faster, more reliable)
build-no-cgo:
	@echo "🔨 Building KubeShadow without CGO..."
	@go mod tidy
	@go clean -cache
	@CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
	@chmod +x kubeshadow
	@echo "✅ KubeShadow built successfully without CGO!"

# Install dependencies
deps:
	@echo "📦 Installing system dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt update && sudo apt install -y libsqlite3-dev build-essential; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y sqlite-devel gcc; \
	elif command -v brew >/dev/null 2>&1; then \
		brew install sqlite; \
	fi
	@echo "📦 Installing Go dependencies..."
	@go mod download
	@go mod tidy

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@go clean -cache -modcache
	@rm -f kubeshadow
	@echo "✅ Clean complete"

# Install to system
install: build
	@echo "📦 Installing KubeShadow to system..."
	@sudo cp kubeshadow /usr/local/bin/
	@echo "✅ KubeShadow installed to /usr/local/bin/"

# Run tests
test:
	@echo "🧪 Running tests..."
	@go test ./...

# Show help
help:
	@echo "KubeShadow Build System"
	@echo "======================"
	@echo "Available targets:"
	@echo "  build        - Build KubeShadow (auto-detects CGO issues)"
	@echo "  build-no-cgo - Build without CGO (recommended for compatibility)"
	@echo "  deps         - Install system and Go dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install to system (/usr/local/bin/)"
	@echo "  test         - Run tests"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Quick start:"
	@echo "  make build   # Build with automatic CGO handling"
	@echo "  ./kubeshadow help"
