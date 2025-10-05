# KubeShadow Lab Module

A comprehensive Kubernetes security testing lab environment that can be deployed to cloud providers or local environments with a single command. This module creates intentionally vulnerable configurations for hands-on security testing and learning.

## 🎯 Overview

The KubeShadow Lab module provides:
- **One-command deployment** to multiple cloud providers and local environments
- **Intentionally vulnerable configurations** for realistic security testing
- **Dashboard integration** for real-time monitoring and result visualization
- **Automated cleanup** to prevent resource waste
- **Educational scenarios** for different skill levels

## 🚀 Quick Start

### Deploy to Local Environment (Minikube)
```bash
# Deploy complete lab environment
./kubeshadow lab --provider minikube

# Start dashboard for monitoring
./kubeshadow dashboard

# Run security reconnaissance
./kubeshadow recon --dashboard

# Clean up when done
./kubeshadow lab cleanup
```

### Deploy to Cloud Provider (AWS)
```bash
# Authenticate with AWS (first time only)
aws configure

# Deploy lab to AWS EKS
./kubeshadow lab --provider aws --region us-west-2

# Run security tests with dashboard
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard

# Clean up entire cluster
./kubeshadow lab cleanup --provider aws --confirm
```

## 📋 Supported Environments

### Cloud Providers
| Provider | Service | Requirements |
|----------|---------|--------------|
| **AWS** | EKS | AWS CLI, eksctl |
| **GCP** | GKE | gcloud CLI |
| **Azure** | AKS | Azure CLI |

### Local Environments
| Environment | Description | Requirements |
|-------------|-------------|--------------|
| **Minikube** | Local Kubernetes | Docker, minikube |
| **Kind** | Kubernetes in Docker | Docker, kind |
| **Local** | Existing cluster | kubectl access |

## 🔧 Command Reference

### Lab Deployment
```bash
./kubeshadow lab [flags]
```

**Flags:**
- `--provider` - Environment type (aws, gcp, azure, minikube, kind, local)
- `--region` - Cloud region (default: us-west-2)
- `--cluster-name` - Cluster name (default: kubeshadow-lab)
- `--skip-auth` - Skip cloud authentication
- `--dashboard` - Enable dashboard integration

**Examples:**
```bash
# Deploy to minikube
./kubeshadow lab --provider minikube

# Deploy to AWS with custom name
./kubeshadow lab --provider aws --region us-east-1 --cluster-name security-lab

# Deploy with dashboard
./kubeshadow lab --provider gcp --dashboard
```

### Lab Cleanup
```bash
./kubeshadow lab cleanup [flags]
```

**Flags:**
- `--confirm` - Skip confirmation prompt
- `--provider` - Provider to cleanup
- `--cluster-name` - Cluster name to cleanup

**Examples:**
```bash
# Clean up lab resources
./kubeshadow lab cleanup

# Clean up specific cluster
./kubeshadow lab cleanup --provider aws --cluster-name security-lab

# Force cleanup without confirmation
./kubeshadow lab cleanup --confirm
```

## 🏗️ Lab Architecture

The lab environment creates a comprehensive Kubernetes setup with intentionally vulnerable configurations. All YAML manifests are located in `modules/lab/manifests/`:

### 📁 Lab Structure
```
modules/lab/
├── README.md                    # This documentation
├── lab.go                      # Main lab deployment logic
├── cleanup.go                  # Lab cleanup functionality
└── manifests/                  # All lab YAML files
    ├── 01-namespace.yaml       # Lab namespaces
    ├── 02-rbac.yaml           # RBAC configurations
    ├── 03-pods.yaml           # Pod configurations
    ├── 04-services.yaml       # Network services
    ├── 05-secrets.yaml        # Secrets
    ├── 06-configmaps.yaml     # Configuration data
    ├── 07-network-policies.yaml # Network policies
    ├── 08-persistent-volumes.yaml # Storage configurations
    ├── setup.sh               # Manual setup script
    ├── cleanup.sh             # Manual cleanup script
    └── LAB_README.md          # Lab environment documentation
```

### 📁 Namespaces
- **`kubeshadow-lab`** - Main lab namespace with vulnerable applications
- **`kubeshadow-secrets`** - Namespace containing sensitive data
- **`kubeshadow-monitoring`** - Monitoring and logging namespace

### 🚀 Pods & Applications
- **Privileged containers** with host access capabilities
- **Web applications** with security vulnerabilities
- **Database pods** with exposed credentials
- **Sidecar containers** for data exfiltration testing
- **Monitoring pods** with excessive permissions

### 🔐 RBAC Configurations
- **Overly permissive roles** for privilege escalation practice
- **Service accounts** with cluster-admin access
- **Role bindings** that violate least privilege
- **Cross-namespace permissions** for lateral movement

### 🌐 Network Services
- **NodePort services** exposing internal applications
- **LoadBalancer services** with external access
- **ClusterIP services** for internal communication
- **Ingress controllers** with misconfigurations

### 🔑 Secrets & ConfigMaps
- **Hardcoded credentials** in various formats
- **API keys** and authentication tokens
- **Database passwords** and connection strings
- **Encryption keys** stored in plaintext

### 🛡️ Network Policies
- **Restrictive policies** for testing bypass techniques
- **Ingress/egress rules** with security gaps
- **Cross-namespace communication** policies
- **Pod-to-pod communication** restrictions

### 💾 Storage Configurations
- **Host path volumes** for container escape testing
- **Shared storage** for data persistence
- **Persistent volumes** with security misconfigurations
- **Volume mounts** with excessive permissions

## 🎓 Learning Scenarios

### Beginner Level
```bash
# 1. Deploy lab environment
./kubeshadow lab --provider minikube --dashboard

# 2. Basic reconnaissance
./kubeshadow recon --dashboard

# 3. Identify vulnerabilities
./kubeshadow recon --namespace kubeshadow-lab --dashboard

# 4. Clean up
./kubeshadow lab cleanup
```

### Intermediate Level
```bash
# 1. Deploy to cloud provider
./kubeshadow lab --provider aws --dashboard

# 2. Advanced reconnaissance
./kubeshadow recon --dashboard

# 3. RBAC exploitation
./kubeshadow rbac-escalate --dashboard

# 4. Container escape testing
./kubeshadow sidecar-inject --dashboard

# 5. Data exfiltration
./kubeshadow data-exfil --presigned-url "YOUR_URL" --dashboard

# 6. Clean up
./kubeshadow lab cleanup --provider aws
```

### Advanced Level
```bash
# 1. Multi-environment testing
./kubeshadow lab --provider aws --dashboard
./kubeshadow recon --dashboard
./kubeshadow lab cleanup

./kubeshadow lab --provider gcp --dashboard
./kubeshadow recon --dashboard
./kubeshadow lab cleanup

# 2. Advanced exploitation techniques
./kubeshadow rbac-escalate --dashboard
./kubeshadow sidecar-inject --dashboard
./kubeshadow kubelet-jack --dashboard

# 3. Stealth techniques
./kubeshadow audit-bypass --dashboard
./kubeshadow dns-cache-poison --dashboard

# 4. Comprehensive data collection
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard
```

## 🔍 Security Vulnerabilities

The lab environment includes intentionally vulnerable configurations across different severity levels:

### 🔴 High Severity
- **Privileged containers** with host access
- **Cluster-admin service accounts** with excessive permissions
- **Exposed secrets** in environment variables and volumes
- **Host network access** for pods
- **Unrestricted API server access**

### 🟡 Medium Severity
- **Overly permissive RBAC** roles and bindings
- **NodePort services** exposing internal applications
- **Shared host volumes** for container escape
- **Weak network policies** with security gaps
- **Default service accounts** with permissions

### 🟢 Low Severity
- **Verbose logging** with sensitive data exposure
- **Unencrypted secrets** in configmaps
- **Weak resource limits** and security contexts
- **Exposed debug endpoints** and health checks
- **Insecure image configurations**

## 🛠️ Prerequisites

### For Cloud Providers
```bash
# AWS
aws --version
eksctl version

# GCP
gcloud --version

# Azure
az --version
```

### For Local Environments
```bash
# Minikube
minikube version
docker --version

# Kind
kind version
docker --version

# General
kubectl version --client
```

### General Requirements
- **KubeShadow binary** in PATH
- **Internet access** for downloading images
- **Sufficient resources** (4GB RAM, 2 CPU cores minimum)
- **Docker** installed and running (for local environments)

## 📊 Dashboard Integration

The lab module integrates seamlessly with the KubeShadow dashboard:

### Starting Dashboard
```bash
# Start dashboard
./kubeshadow dashboard

# Access dashboard
# Navigate to http://localhost:8080
```

### Running Commands with Dashboard
```bash
# All commands support dashboard integration
./kubeshadow lab --dashboard
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard
./kubeshadow data-exfil --presigned-url "URL" --dashboard
```

### Dashboard Features
- **Real-time monitoring** of command execution
- **Result visualization** with charts and graphs
- **Export functionality** for CSV and PDF reports
- **Historical data** tracking
- **Interactive interface** for exploration

## 🧹 Cleanup Procedures

### Resource Cleanup
```bash
# Remove lab resources only
./kubeshadow lab cleanup

# Remove with confirmation
./kubeshadow lab cleanup --confirm
```

### Cluster Cleanup
```bash
# Remove entire cluster (cloud providers)
./kubeshadow lab cleanup --provider aws --cluster-name my-lab

# Force cleanup without confirmation
./kubeshadow lab cleanup --provider gcp --confirm
```

### Manual Cleanup
```bash
# Remove specific resources
kubectl delete namespace kubeshadow-lab
kubectl delete namespace kubeshadow-secrets
kubectl delete namespace kubeshadow-monitoring

# Or use the manual cleanup script
cd modules/lab/manifests
./cleanup.sh

# Remove cluster (cloud providers)
# AWS
eksctl delete cluster --name kubeshadow-lab

# GCP
gcloud container clusters delete kubeshadow-lab

# Azure
az aks delete --name kubeshadow-lab --resource-group kubeshadow-lab-rg
```

### Manual Setup (Alternative)
```bash
# If you prefer manual setup instead of the lab command
cd modules/lab/manifests
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

## 🚨 Security Considerations

### ⚠️ Important Security Notes

1. **Lab Environment Only** - Never deploy these configurations in production
2. **Network Isolation** - Ensure lab clusters are isolated from production networks
3. **Resource Monitoring** - Monitor cloud resource usage to prevent cost overruns
4. **Access Control** - Limit access to lab environments and credentials
5. **Data Sensitivity** - Never use real sensitive data in lab environments
6. **Cleanup Responsibility** - Always clean up resources after use

### Best Practices
- **Use separate AWS/GCP/Azure accounts** for lab environments
- **Set up billing alerts** to monitor cloud costs
- **Implement network isolation** between lab and production
- **Regular cleanup** of unused resources
- **Document findings** for learning purposes

## 🔧 Troubleshooting

### Common Issues

**Cluster Creation Fails:**
```bash
# Check cloud provider authentication
aws sts get-caller-identity
gcloud auth list
az account show

# Verify required tools are installed
eksctl version
gcloud --version
az --version
```

**Pods Not Starting:**
```bash
# Check resource availability
kubectl describe pods -n kubeshadow-lab
kubectl get events -n kubeshadow-lab

# Check node resources
kubectl top nodes
kubectl describe nodes
```

**Dashboard Not Accessible:**
```bash
# Check dashboard status
./kubeshadow dashboard --port 8080

# Check if port is available
netstat -tulpn | grep 8080

# Try different port
./kubeshadow dashboard --port 8081
```

**Authentication Issues:**
```bash
# AWS
aws configure list
aws sts get-caller-identity

# GCP
gcloud auth list
gcloud config list

# Azure
az account show
az login
```

### Getting Help

1. **Check logs**: `kubectl logs -n kubeshadow-lab`
2. **Verify resources**: `kubectl get all -n kubeshadow-lab`
3. **Test connectivity**: `kubectl cluster-info`
4. **Review documentation**: Check this README and lab documentation
5. **Check prerequisites**: Ensure all required tools are installed

## 📚 Additional Resources

### Documentation
- [KubeShadow Main Documentation](../../README.md)
- [Lab Environment Setup](../../lab/README.md)
- [Dashboard User Guide](../../docs/dashboard.md)
- [Security Testing Guide](../../docs/security-testing.md)

### Examples
- [Lab Usage Examples](../../examples/lab-usage.md)
- [Security Testing Scenarios](../../examples/security-scenarios.md)
- [Dashboard Workflows](../../examples/dashboard-workflows.md)

### Learning Resources
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Container Security Guidelines](https://kubernetes.io/docs/concepts/containers/security-context/)
- [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

## 🎯 Use Cases

### Educational Institutions
- **Security courses** with hands-on lab environments
- **Research projects** requiring isolated testing environments
- **Student exercises** with guided scenarios
- **Instructor demonstrations** with real-time monitoring

### Corporate Training
- **Security awareness** training for development teams
- **Red team exercises** with controlled environments
- **Compliance testing** with realistic scenarios
- **Incident response** practice with vulnerable configurations

### Security Professionals
- **Penetration testing** practice with Kubernetes
- **Vulnerability research** in controlled environments
- **Tool development** and testing
- **Certification preparation** for security exams

## 🤝 Contributing

We welcome contributions to improve the lab module:

1. **Report issues** with lab deployments
2. **Suggest new scenarios** for educational value
3. **Improve documentation** and examples
4. **Add new cloud providers** or local environments
5. **Enhance security configurations** for realistic testing

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## 🙏 Acknowledgments

- **Kubernetes community** for the excellent platform
- **Security researchers** who identified the vulnerabilities we simulate
- **Educational institutions** that provided feedback on lab scenarios
- **Open source contributors** who made this project possible

---

**Happy Learning! 🚀**

The KubeShadow Lab module provides endless possibilities for Kubernetes security learning. Experiment, explore, and always practice responsibly!

For questions, issues, or contributions, please visit our [GitHub repository](https://github.com/kubeshadow/kubeshadow).
