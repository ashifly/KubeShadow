#!/bin/bash
# KubeShadow Automated Setup Script
# Handles all dependencies and CGO issues automatically

set -e  # Exit on any error

echo "🎯 KubeShadow Automated Setup"
echo "============================"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go 1.21+ (Required by KubeShadow)..."
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export GOBIN=$GOPATH/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.5.linux-amd64.tar.gz
else
    echo "✅ Go is already installed: $(go version)"
fi

# Install system dependencies
echo "📦 Installing system dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt update -qq
    sudo apt install -y libsqlite3-dev build-essential
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y sqlite-devel gcc
elif command -v brew >/dev/null 2>&1; then
    brew install sqlite
fi

# Clean and prepare
echo "🧹 Cleaning previous builds..."
go clean -cache -modcache 2>/dev/null || true

# Download dependencies
echo "📦 Downloading Go dependencies..."
go mod download
go mod tidy

# Build with automatic CGO fallback
echo "🔨 Building KubeShadow..."
if go build -o kubeshadow . 2>/dev/null; then
    echo "✅ Build successful with CGO"
else
    echo "⚠️  CGO build failed, trying without CGO (more compatible)..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
    echo "✅ Build successful without CGO"
fi

# Make executable
chmod +x kubeshadow

# Test the build
echo "🧪 Testing build..."
if ./kubeshadow help >/dev/null 2>&1; then
    echo "✅ KubeShadow is working correctly!"
    echo ""
    echo "🎉 Setup complete! You can now use:"
    echo "   ./kubeshadow help"
    echo "   ./kubeshadow recon --dashboard"
    echo "   ./kubeshadow lab --provider minikube"
else
    echo "❌ Build test failed. Trying alternative build..."
    CGO_ENABLED=0 go build -o kubeshadow .
    chmod +x kubeshadow
    if ./kubeshadow help >/dev/null 2>&1; then
        echo "✅ Alternative build successful!"
    else
        echo "❌ Setup failed. Please check the troubleshooting section in README.md"
        exit 1
    fi
fi

echo ""
echo "🚀 KubeShadow is ready to use!"
echo "💡 Run './kubeshadow help' to see available commands" 