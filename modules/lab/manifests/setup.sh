#!/bin/bash

# KubeShadow Lab Setup Script
# This script sets up the complete lab environment

echo "🎯 Setting up KubeShadow Lab Environment..."

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed or not in PATH"
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster"
    echo "Please ensure your cluster is running and kubectl is configured"
    exit 1
fi

echo "✅ Kubernetes cluster is accessible"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create namespaces
echo "📁 Creating namespaces..."
kubectl apply -f "$SCRIPT_DIR/01-namespace.yaml"

# Set up RBAC
echo "🔐 Setting up RBAC configurations..."
kubectl apply -f "$SCRIPT_DIR/02-rbac.yaml"

# Deploy pods
echo "🚀 Deploying pods..."
kubectl apply -f "$SCRIPT_DIR/03-pods.yaml"

# Create services
echo "🌐 Creating services..."
kubectl apply -f "$SCRIPT_DIR/04-services.yaml"

# Create secrets
echo "🔑 Creating secrets..."
kubectl apply -f "$SCRIPT_DIR/05-secrets.yaml"

# Create configmaps
echo "⚙️ Creating configmaps..."
kubectl apply -f "$SCRIPT_DIR/06-configmaps.yaml"

# Apply network policies
echo "🛡️ Applying network policies..."
kubectl apply -f "$SCRIPT_DIR/07-network-policies.yaml"

# Create persistent volumes
echo "💾 Creating persistent volumes..."
kubectl apply -f "$SCRIPT_DIR/08-persistent-volumes.yaml"

# Wait for pods to be ready
echo "⏳ Waiting for pods to be ready..."
kubectl wait --for=condition=Ready pod --all -n kubeshadow-lab --timeout=60s

# Display lab status
echo ""
echo "🎉 Lab environment setup complete!"
echo ""
echo "📊 Lab Status:"
kubectl get pods -n kubeshadow-lab
echo ""
kubectl get services -n kubeshadow-lab
echo ""
kubectl get secrets -n kubeshadow-lab
echo ""

echo "🎓 Ready for KubeShadow exercises!"
echo ""
echo "Next steps:"
echo "1. Start KubeShadow dashboard: ./kubeshadow dashboard"
echo "2. Run reconnaissance: ./kubeshadow recon --dashboard"
echo "3. Explore the lab environment and identify security issues"
echo ""
echo "Happy learning! 🚀"
