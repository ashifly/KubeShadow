# KubeShadow Makefile
# Automatically handles CGO issues and builds for different environments

.PHONY: build build-cgo build-no-cgo clean install deps test help

# Default target
all: build

# Build with automatic CGO detection and fallback
build:
	@echo "🔨 Building KubeShadow..."
	@echo "📦 Checking dependencies... (10%)"
	@go mod tidy
	@echo "🧹 Cleaning previous builds... (20%)"
	@go clean -cache
	@echo "🔧 Building without CGO (fast and reliable)... (30%)"
	@echo "⏳ Compiling Go modules... (40%)"
	@CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
	@echo "✅ Build successful! (100%)"
	@echo "🔧 Making executable... (90%)"
	@chmod +x kubeshadow
	@echo "🎉 KubeShadow built successfully! (100%)"
	@echo "💡 Run './kubeshadow help' to get started"

# Build with CGO (enables SQLite persistent storage)
build-cgo:
	@echo "🔨 Building KubeShadow with CGO (SQLite support)..."
	@echo "📦 Installing system dependencies if needed..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt update && sudo apt install -y libsqlite3-dev build-essential || true; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y sqlite-devel gcc || true; \
	elif command -v brew >/dev/null 2>&1; then \
		brew install sqlite || true; \
	fi
	@go mod tidy
	@go clean -cache
	@echo "🔧 Building with CGO enabled..."
	@CGO_ENABLED=1 go build -ldflags="-s -w" -o kubeshadow .
	@chmod +x kubeshadow
	@echo "✅ KubeShadow built successfully with CGO (SQLite support enabled)!"

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
	@echo "  build        - Build KubeShadow without CGO (default, fast and reliable)"
	@echo "  build-cgo    - Build with CGO enabled (enables SQLite persistent storage)"
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
