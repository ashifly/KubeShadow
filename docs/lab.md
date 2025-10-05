# KubeShadow Lab Module

The KubeShadow Lab module provides a complete, automated lab environment for Kubernetes security testing and learning. It can deploy a full lab environment to cloud providers or local Kubernetes clusters with intentionally vulnerable configurations for hands-on security practice.

## 🎯 Overview

The lab module creates a complete Kubernetes environment with:
- **Intentionally vulnerable configurations** for security testing
- **Multiple attack vectors** to practice reconnaissance and exploitation
- **Real-world scenarios** that mirror production misconfigurations
- **Dashboard integration** for real-time monitoring of security tests

## 🚀 Quick Start

### Deploy to Local Environment (Minikube)
```bash
# Deploy lab to minikube
./kubeshadow lab --provider minikube

# Start dashboard
./kubeshadow dashboard

# Run reconnaissance
./kubeshadow recon --dashboard
```

### Deploy to Cloud Provider
```bash
# Deploy to AWS EKS
./kubeshadow lab --provider aws --region us-west-2

# Deploy to GCP GKE  
./kubeshadow lab --provider gcp --region us-central1

# Deploy to Azure AKS
./kubeshadow lab --provider azure --region eastus
```

### Clean Up Lab Environment
```bash
# Clean up lab resources only
./kubeshadow lab cleanup

# Clean up entire cluster (cloud providers)
./kubeshadow lab cleanup --provider aws --cluster-name kubeshadow-lab
```

## 📋 Supported Providers

### Cloud Providers
- **AWS EKS** - Amazon Elastic Kubernetes Service
- **GCP GKE** - Google Kubernetes Engine  
- **Azure AKS** - Azure Kubernetes Service

### Local Environments
- **Minikube** - Local Kubernetes development
- **Kind** - Kubernetes in Docker
- **Local** - Existing local cluster

## 🔧 Command Options

### Lab Deployment
```bash
./kubeshadow lab [flags]
```

**Flags:**
- `--provider` - Cloud provider or local environment (default: minikube)
- `--region` - Cloud region for cloud providers (default: us-west-2)
- `--cluster-name` - Name for the Kubernetes cluster (default: kubeshadow-lab)
- `--skip-auth` - Skip cloud authentication (use existing credentials)

### Lab Cleanup
```bash
./kubeshadow lab cleanup [flags]
```

**Flags:**
- `--confirm` - Skip confirmation prompt
- `--provider` - Provider to cleanup (default: local)
- `--cluster-name` - Name of the cluster to cleanup (default: kubeshadow-lab)

## 🏗️ Lab Architecture

The lab environment includes:

### 📁 Namespaces
- `kubeshadow-lab` - Main lab namespace
- `kubeshadow-secrets` - Namespace with sensitive data
- `kubeshadow-monitoring` - Monitoring and logging

### 🚀 Pods
- **Privileged containers** with host access
- **Sidecar containers** for data exfiltration
- **Web applications** with security vulnerabilities
- **Database pods** with exposed credentials

### 🔐 RBAC
- **Overly permissive roles** for privilege escalation
- **Service accounts** with excessive permissions
- **Cluster-admin bindings** for testing

### 🌐 Services
- **NodePort services** exposing internal applications
- **LoadBalancer services** with external access
- **ClusterIP services** for internal communication

### 🔑 Secrets & ConfigMaps
- **Hardcoded credentials** in various formats
- **API keys** and tokens
- **Database passwords** and connection strings

### 🛡️ Network Policies
- **Restrictive policies** for testing bypass techniques
- **Ingress/egress rules** for network security testing

### 💾 Persistent Volumes
- **Host path volumes** for container escape testing
- **Shared storage** for data persistence

## 🎓 Learning Scenarios

### 1. Reconnaissance
```bash
# Discover cluster information
./kubeshadow recon --dashboard

# Identify security misconfigurations
./kubeshadow recon --namespace kubeshadow-lab --dashboard
```

### 2. RBAC Exploitation
```bash
# Test privilege escalation
./kubeshadow rbac-escalate --dashboard

# Enumerate permissions
./kubeshadow recon --rbac --dashboard
```

### 3. Container Escape
```bash
# Test privileged container access
./kubeshadow sidecar-inject --dashboard

# Attempt host access
./kubeshadow kubelet-jack --dashboard
```

### 4. Data Exfiltration
```bash
# Collect and exfiltrate data
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard
```

## 🔍 Security Vulnerabilities

The lab environment includes intentionally vulnerable configurations:

### High Severity
- **Privileged containers** with host access
- **Cluster-admin service accounts**
- **Exposed secrets** in environment variables
- **Host network access** for pods

### Medium Severity  
- **Overly permissive RBAC** roles
- **NodePort services** exposing internal apps
- **Shared host volumes** for container escape
- **Weak network policies**

### Low Severity
- **Verbose logging** with sensitive data
- **Unencrypted secrets** in configmaps
- **Default service accounts** with permissions

## 🛠️ Prerequisites

### For Cloud Providers
- **AWS CLI** configured with appropriate permissions
- **GCP CLI** authenticated with project access
- **Azure CLI** logged in with subscription access

### For Local Environments
- **Docker** installed and running
- **Minikube** or **Kind** installed
- **kubectl** configured

### General Requirements
- **KubeShadow binary** in PATH
- **Internet access** for downloading images
- **Sufficient resources** (4GB RAM, 2 CPU cores minimum)

## 📊 Monitoring & Dashboard

The lab integrates with the KubeShadow dashboard for real-time monitoring:

1. **Start dashboard**: `./kubeshadow dashboard`
2. **Open browser**: Navigate to `http://localhost:8080`
3. **Run commands**: Use `--dashboard` flag with any command
4. **Monitor results**: View real-time command outputs and results

## 🧹 Cleanup Procedures

### Resource Cleanup
```bash
# Remove lab resources only
./kubeshadow lab cleanup
```

### Cluster Cleanup
```bash
# Remove entire cluster (cloud providers)
./kubeshadow lab cleanup --provider aws --cluster-name kubeshadow-lab
```

### Manual Cleanup
```bash
# Remove specific resources
kubectl delete namespace kubeshadow-lab
kubectl delete namespace kubeshadow-secrets
kubectl delete namespace kubeshadow-monitoring
```

## 🚨 Security Considerations

⚠️ **Important Security Notes:**

1. **Lab Environment Only** - Never deploy these configurations in production
2. **Network Isolation** - Ensure lab clusters are isolated from production
3. **Resource Limits** - Monitor resource usage to prevent cost overruns
4. **Access Control** - Limit access to lab environments
5. **Data Sensitivity** - No real sensitive data should be used in labs

## 🎯 Best Practices

### For Students
- **Start with reconnaissance** before attempting exploitation
- **Document findings** using the dashboard export features
- **Practice defensive techniques** alongside offensive testing
- **Understand the business impact** of each vulnerability

### For Instructors
- **Monitor student progress** through the dashboard
- **Provide guided scenarios** based on lab configurations
- **Encourage documentation** of findings and remediation steps
- **Emphasize responsible disclosure** practices

## 🔧 Troubleshooting

### Common Issues

**Cluster Creation Fails:**
```bash
# Check cloud provider authentication
aws sts get-caller-identity
gcloud auth list
az account show
```

**Pods Not Starting:**
```bash
# Check resource availability
kubectl describe pods -n kubeshadow-lab
kubectl get events -n kubeshadow-lab
```

**Dashboard Not Accessible:**
```bash
# Check dashboard status
./kubeshadow dashboard --port 8080
# Check if port is available
netstat -tulpn | grep 8080
```

### Getting Help

1. **Check logs**: `kubectl logs -n kubeshadow-lab`
2. **Verify resources**: `kubectl get all -n kubeshadow-lab`
3. **Test connectivity**: `kubectl cluster-info`
4. **Review documentation**: Check this guide and lab README

## 📚 Additional Resources

- [KubeShadow Documentation](../README.md)
- [Lab Environment Setup](../lab/README.md)
- [Security Testing Guide](../docs/security-testing.md)
- [Dashboard User Guide](../docs/dashboard.md)

---

**Happy Learning! 🚀**

The KubeShadow Lab provides a safe, controlled environment for mastering Kubernetes security testing. Practice responsibly and always follow ethical guidelines!
