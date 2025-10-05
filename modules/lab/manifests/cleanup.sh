#!/bin/bash

# KubeShadow Lab Cleanup Script
# This script removes all lab resources

echo "🧹 Cleaning up KubeShadow Lab Environment..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Remove persistent volumes
echo "💾 Removing persistent volumes..."
kubectl delete -f "$SCRIPT_DIR/08-persistent-volumes.yaml" --ignore-not-found=true

# Remove network policies
echo "🛡️ Removing network policies..."
kubectl delete -f "$SCRIPT_DIR/07-network-policies.yaml" --ignore-not-found=true

# Remove configmaps
echo "⚙️ Removing configmaps..."
kubectl delete -f "$SCRIPT_DIR/06-configmaps.yaml" --ignore-not-found=true

# Remove secrets
echo "🔑 Removing secrets..."
kubectl delete -f "$SCRIPT_DIR/05-secrets.yaml" --ignore-not-found=true

# Remove services
echo "🌐 Removing services..."
kubectl delete -f "$SCRIPT_DIR/04-services.yaml" --ignore-not-found=true

# Remove pods
echo "🚀 Removing pods..."
kubectl delete -f "$SCRIPT_DIR/03-pods.yaml" --ignore-not-found=true

# Remove RBAC
echo "🔐 Removing RBAC configurations..."
kubectl delete -f "$SCRIPT_DIR/02-rbac.yaml" --ignore-not-found=true

# Remove namespaces
echo "📁 Removing namespaces..."
kubectl delete -f "$SCRIPT_DIR/01-namespace.yaml" --ignore-not-found=true

echo ""
echo "✅ Lab environment cleanup complete!"
echo "All KubeShadow lab resources have been removed."
