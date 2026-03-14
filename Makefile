# KubeShadow Makefile

.PHONY: build rebuild build-cgo build-no-cgo clean deps test install help

# ── Fast incremental build (default) ──────────────────────────────────────────
# CGO_ENABLED=0: skips compiling go-sqlite3 C code (~200 C files).
# Dashboard falls back to in-memory mode automatically — no functionality lost.
# Does NOT clear the cache; uses Go's incremental compilation.
build:
	@echo "🔨 Building KubeShadow (incremental, CGO off)..."
	@CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
	@chmod +x kubeshadow
	@echo "✅ Done — ./kubeshadow help to get started"

# Alias
fast: build

# ── Full clean rebuild (use when deps change or cache is stale) ───────────────
rebuild:
	@echo "🔨 Full rebuild (cleaning cache first)..."
	@go mod tidy
	@go clean -cache
	@CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
	@chmod +x kubeshadow
	@echo "✅ Full rebuild complete"

# ── Build with CGO (enables SQLite persistent dashboard storage) ──────────────
build-cgo:
	@echo "🔨 Building with CGO (SQLite support)..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get install -y --no-install-recommends libsqlite3-dev build-essential || true; \
	elif command -v brew >/dev/null 2>&1; then \
		brew install sqlite || true; \
	fi
	@CGO_ENABLED=1 go build -ldflags="-s -w" -o kubeshadow .
	@chmod +x kubeshadow
	@echo "✅ CGO build complete (SQLite dashboard storage enabled)"

# Alias
build-no-cgo: build

# ── Download dependencies (one-time setup) ───────────────────────────────────
deps:
	@echo "📦 Downloading Go modules..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencies ready"

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	@go clean
	@rm -f kubeshadow
	@echo "✅ Cleaned build artifacts (cache preserved)"

clean-all:
	@go clean -cache -modcache
	@rm -f kubeshadow
	@echo "✅ Full clean (cache + module cache cleared)"

# ── Install to system ─────────────────────────────────────────────────────────
install: build
	@sudo cp kubeshadow /usr/local/bin/
	@echo "✅ Installed to /usr/local/bin/kubeshadow"

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	@CGO_ENABLED=0 go test ./...

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo "KubeShadow Build Targets"
	@echo "========================"
	@echo "  make build       Fast incremental build, CGO off (default)"
	@echo "  make rebuild     Full clean rebuild — use after dep changes"
	@echo "  make build-cgo   Build with SQLite dashboard storage (needs gcc)"
	@echo "  make deps        Download/verify Go modules (run once)"
	@echo "  make clean       Remove binary (keeps build cache)"
	@echo "  make clean-all   Remove binary + full cache wipe"
	@echo "  make install     Install to /usr/local/bin/"
	@echo "  make test        Run tests"
	@echo ""
	@echo "Why is the build fast?"
	@echo "  - Incremental: only changed packages recompile"
	@echo "  - CGO_ENABLED=0: skips sqlite3 C compilation"
	@echo "  - go mod tidy only runs on 'rebuild' or 'deps'"
