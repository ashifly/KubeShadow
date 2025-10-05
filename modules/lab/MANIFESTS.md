# KubeShadow Lab Manifests

This directory contains all the YAML manifests and scripts for the KubeShadow lab environment.

## 📁 File Structure

```
manifests/
├── 01-namespace.yaml           # Lab namespaces
├── 02-rbac.yaml               # RBAC configurations (intentionally vulnerable)
├── 03-pods.yaml               # Pod configurations with security issues
├── 04-services.yaml           # Network services and exposures
├── 05-secrets.yaml            # Secrets with different security levels
├── 06-configmaps.yaml        # Configuration data for testing
├── 07-network-policies.yaml   # Network security policies
├── 08-persistent-volumes.yaml # Storage configurations
├── setup.sh                   # Manual setup script
├── cleanup.sh                 # Manual cleanup script
└── LAB_README.md              # Lab environment documentation
```

## 🚀 Usage

### Automated Deployment (Recommended)
```bash
# Deploy complete lab environment
./kubeshadow lab --provider minikube

# Deploy to cloud provider
./kubeshadow lab --provider aws --region us-west-2

# Clean up
./kubeshadow lab cleanup
```

### Manual Deployment
```bash
# Navigate to manifests directory
cd modules/lab/manifests

# Run setup script
./setup.sh

# Or apply files individually
kubectl apply -f 01-namespace.yaml
kubectl apply -f 02-rbac.yaml
kubectl apply -f 03-pods.yaml
kubectl apply -f 04-services.yaml
kubectl apply -f 05-secrets.yaml
kubectl apply -f 06-configmaps.yaml
kubectl apply -f 07-network-policies.yaml
kubectl apply -f 08-persistent-volumes.yaml
```

### Manual Cleanup
```bash
# Navigate to manifests directory
cd modules/lab/manifests

# Run cleanup script
./cleanup.sh

# Or delete files individually
kubectl delete -f 08-persistent-volumes.yaml --ignore-not-found=true
kubectl delete -f 07-network-policies.yaml --ignore-not-found=true
kubectl delete -f 06-configmaps.yaml --ignore-not-found=true
kubectl delete -f 05-secrets.yaml --ignore-not-found=true
kubectl delete -f 04-services.yaml --ignore-not-found=true
kubectl delete -f 03-pods.yaml --ignore-not-found=true
kubectl delete -f 02-rbac.yaml --ignore-not-found=true
kubectl delete -f 01-namespace.yaml --ignore-not-found=true
```

## 🔍 Security Vulnerabilities

Each manifest file contains intentionally vulnerable configurations for security testing:

### 01-namespace.yaml
- Creates multiple namespaces for testing
- Sets up namespace isolation scenarios

### 02-rbac.yaml
- **Overly permissive roles** for privilege escalation
- **Service accounts** with excessive permissions
- **Cluster-admin bindings** for testing
- **Cross-namespace permissions** for lateral movement

### 03-pods.yaml
- **Privileged containers** with host access
- **Sidecar containers** for data exfiltration
- **Web applications** with security vulnerabilities
- **Database pods** with exposed credentials
- **Monitoring pods** with excessive permissions

### 04-services.yaml
- **NodePort services** exposing internal applications
- **LoadBalancer services** with external access
- **ClusterIP services** for internal communication
- **Ingress controllers** with misconfigurations

### 05-secrets.yaml
- **Hardcoded credentials** in various formats
- **API keys** and authentication tokens
- **Database passwords** and connection strings
- **Encryption keys** stored in plaintext

### 06-configmaps.yaml
- **Sensitive data** in configuration files
- **API endpoints** with credentials
- **Debug information** with sensitive details
- **Environment variables** with secrets

### 07-network-policies.yaml
- **Restrictive policies** for testing bypass techniques
- **Ingress/egress rules** with security gaps
- **Cross-namespace communication** policies
- **Pod-to-pod communication** restrictions

### 08-persistent-volumes.yaml
- **Host path volumes** for container escape testing
- **Shared storage** for data persistence
- **Persistent volumes** with security misconfigurations
- **Volume mounts** with excessive permissions

## 🎓 Learning Objectives

Students will learn to:
- **Identify security misconfigurations** in Kubernetes manifests
- **Practice reconnaissance techniques** on vulnerable environments
- **Test RBAC configurations** and privilege escalation
- **Understand container security** boundaries and escape techniques
- **Analyze network policies** and bypass restrictions
- **Handle secrets management** and data exposure
- **Use KubeShadow tools** for security testing

## 🛠️ Prerequisites

- **Kubernetes cluster** (minikube, kind, or cloud provider)
- **kubectl** configured and accessible
- **Docker** installed (for local environments)
- **KubeShadow binary** in PATH

## 📊 Monitoring

The lab environment integrates with the KubeShadow dashboard:

```bash
# Start dashboard
./kubeshadow dashboard

# Run commands with monitoring
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard
./kubeshadow data-exfil --presigned-url "URL" --dashboard
```

## 🧹 Cleanup

Always clean up lab environments after use:

```bash
# Automated cleanup
./kubeshadow lab cleanup

# Manual cleanup
cd modules/lab/manifests
./cleanup.sh
```

## ⚠️ Security Warning

**NEVER deploy these configurations in production!**

These manifests contain intentionally vulnerable configurations for educational purposes only. They should only be used in isolated lab environments.

## 📚 Additional Resources

- [KubeShadow Lab Module README](../README.md)
- [Lab Usage Examples](../../examples/lab-usage.md)
- [Security Testing Guide](../../docs/security-testing.md)
- [Dashboard User Guide](../../docs/dashboard.md)

---

**Happy Learning! 🚀**

The KubeShadow Lab provides a safe, controlled environment for mastering Kubernetes security testing. Practice responsibly and always follow ethical guidelines!
