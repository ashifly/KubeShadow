# KubeShadow

KubeShadow is a powerful Kubernetes security testing and exploitation toolkit designed for red team operations and security assessments. It provides a comprehensive suite of modules for testing cluster security, identifying misconfigurations, and validating security controls.

## Features

### Core Capabilities
- **Modular Architecture**: Extensible plugin system for custom functionality
- **Multiple Attack Vectors**: Support for various exploitation techniques
- **Comprehensive Reconnaissance**: Detailed cluster and cloud environment analysis
- **Stealth Operations**: Low-visibility testing capabilities
- **Cloud Integration**: Multi-cloud provider support (AWS, GCP, Azure)
- **Out-of-Cluster Operations**: External registry and infrastructure attacks
- **Robust Error Handling**: Comprehensive error management and reporting
- **Detailed Logging**: Configurable logging with level filtering

### Module Categories

#### 1. Reconnaissance (`modules/recon/`)
- **Cluster Reconnaissance**: Comprehensive Kubernetes cluster information gathering
  - RBAC analysis
  - Network policy enumeration
  - Service account discovery
  - Pod security context analysis
  - Node information gathering
    
#### 2. Cluster Exploitation (`modules/cluster_exploit/`)
- **ETCD Injection**: Direct pod injection via etcd
- **Kubelet Exploitation**: Kubelet API exploitation and hijacking
- **Sidecar Injection**: Pod sidecar container injection
- **RBAC Escalation**: RBAC privilege escalation and permission analysis
- **Namespace Pivot**: Cross-namespace access and privilege movement

#### 3. Cloud Exploitation (`modules/multi_cloud/`)
- **Metadata Hijacking**: Cloud metadata service exploitation
- **Cloud Privilege Escalation**: Cloud IAM privilege escalation
- **Assume Role Abuse**: Cloud role assumption and token abuse
- **Cloud Elevator**: Automated cloud privilege escalation paths

#### 4. Stealth Operations (`modules/stealth/`)
- **Audit Bypass**: Audit policy bypass testing and analysis
- **DNS Cache Poisoning**: DNS cache poisoning and spoofing attacks
- **Cleanup Operations**: Evidence removal and operation cleanup
  - Log sanitization
  - Resource cleanup
  - Operation trace removal
  - Evidence elimination

#### 5. Out-of-Cluster Operations (`modules/out_cluster/`)
- **Registry Backdoor**: Container registry exploitation and backdooring
  - Image tampering
  - Credential theft
  - Supply chain attacks

## Installation

```bash
# Install from source
go get github.com/ashifly/KubeShadow

# Build from source (automatically handles CGO issues)
git clone https://github.com/ashifly/KubeShadow
cd KubeShadow
make build
```

**Or use the automated build script:**
```bash
# One-command build (handles all dependencies automatically)
./setup.sh
```

## 🛠️ Troubleshooting Build Issues

**Note:** The automated setup script (`./setup.sh`) and Makefile (`make build`) handle most build issues automatically. Only use manual troubleshooting if the automated methods fail.

### Manual Build (if automated setup fails)

**Quick Fix - Build without CGO:**
```bash
# This works on most systems
CGO_ENABLED=0 go build -o kubeshadow .
chmod +x kubeshadow
./kubeshadow help
```

**Full Manual Build:**
```bash
# Install dependencies
sudo apt update && sudo apt install -y libsqlite3-dev build-essential

# Clean and build
go clean -modcache
go mod tidy
go build -o kubeshadow .
chmod +x kubeshadow
./kubeshadow help
```

### Advanced Troubleshooting

**If you still get segmentation faults:**
```bash
# Try static build
CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .

# Or use the Makefile
make build-no-cgo
```

**Check your environment:**
```bash
# Verify Go installation
go version

# Check if all dependencies are available
go mod download
```

## Quick Start

1. Basic reconnaissance:
```bash
# Full cluster analysis
kubeshadow recon --kubeconfig ~/.kube/config

# Stealth mode (minimal API calls)
kubeshadow recon --stealth

# Only Kubernetes recon
kubeshadow recon --k8s-only
```

2. View available commands:
```bash
kubeshadow --help
```

## 🧪 Creating a Lab Environment

KubeShadow includes a comprehensive lab module that creates intentionally vulnerable Kubernetes environments for hands-on security practice. This is perfect for learning, testing, and demonstrating Kubernetes security concepts.

### Prerequisites & Cloud Setup

**Before deploying lab environments, configure your cloud credentials:**

**AWS Setup:**
```bash
# Install AWS CLI and eksctl
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Configure AWS credentials
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

**GCP Setup:**
```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Authenticate and set project
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com
```

**Azure Setup:**
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login and set subscription
az login
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# Create resource group (if needed)
az group create --name kubeshadow-lab-rg --location eastus
```

**Local Environment Setup:**
```bash
# Install Docker
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl start docker
sudo usermod -aG docker $USER

# Install Minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

### Quick Lab Setup

**Local Environment (Minikube):**
```bash
# Deploy complete lab environment
./kubeshadow lab --provider minikube --dashboard

# Run security reconnaissance
./kubeshadow recon --dashboard

# Clean up when done
./kubeshadow lab cleanup
```

**Cloud Environment (AWS/GCP/Azure):**
```bash
# Deploy to AWS EKS (choose any region)
./kubeshadow lab --provider aws --region us-west-2 --dashboard

# Deploy to GCP GKE (choose any region)
./kubeshadow lab --provider gcp --region us-central1 --dashboard

# Deploy to Azure AKS (choose any region)
./kubeshadow lab --provider azure --region eastus --dashboard

# Clean up lab resources only (keeps cluster)
./kubeshadow lab cleanup

# Clean up lab resources AND delete entire cluster
./kubeshadow lab cleanup --provider aws --confirm
```

### Lab Features

The lab environment includes:
- **Intentionally vulnerable configurations** for realistic testing
- **Multiple attack scenarios** across different skill levels
- **Dashboard integration** for real-time monitoring and visualization
- **Automated cleanup** to prevent resource waste
- **Educational scenarios** with step-by-step guides

### Learning Paths

**Beginner Level:**
```bash
# 1. Deploy lab
./kubeshadow lab --provider minikube --dashboard

# 2. Basic reconnaissance
./kubeshadow recon --dashboard

# 3. Identify vulnerabilities
./kubeshadow recon --namespace kubeshadow-lab --dashboard

# 4. Clean up lab resources (keeps cluster)
./kubeshadow lab cleanup
```

**Intermediate Level:**
```bash
# 1. Deploy to cloud
./kubeshadow lab --provider aws --dashboard

# 2. Advanced reconnaissance
./kubeshadow recon --dashboard

# 3. RBAC exploitation
./kubeshadow rbac-escalate --dashboard

# 4. Container escape testing
./kubeshadow sidecar-inject --dashboard

# 5. Clean up lab resources (keeps cluster)
./kubeshadow lab cleanup
```

**Advanced Level:**
```bash
# 1. Multi-environment testing
./kubeshadow lab --provider aws --dashboard
./kubeshadow recon --dashboard
./kubeshadow lab cleanup --provider aws --confirm  # Deletes entire cluster

# 2. Advanced exploitation
./kubeshadow rbac-escalate --dashboard
./kubeshadow kubelet-jack --dashboard

# 3. Stealth techniques
./kubeshadow audit-bypass --dashboard
./kubeshadow dns-cache-poison --dashboard

# 4. Clean up lab resources (keeps cluster)
./kubeshadow lab cleanup
```

### Lab Vulnerabilities

The lab includes intentionally vulnerable configurations:
- **Privileged containers** with host access
- **Overly permissive RBAC** roles and bindings
- **Exposed secrets** in environment variables
- **Host network access** for pods
- **Weak network policies** with security gaps
- **Default service accounts** with excessive permissions

### Prerequisites

**For Local Environments:**
- Docker installed and running
- Minikube or Kind
- kubectl configured

**For Cloud Providers:**
- Cloud credentials configured (see Prerequisites & Cloud Setup section above)
- AWS CLI and eksctl (for AWS)
- gcloud CLI (for GCP) 
- Azure CLI (for Azure)

### Dashboard Integration

The lab integrates seamlessly with the KubeShadow dashboard:
```bash
# Start dashboard
./kubeshadow dashboard

# Access at http://localhost:8080
# View real-time command execution and results
# Export findings as CSV or PDF
```

For detailed lab documentation, see [modules/lab/README.md](modules/lab/README.md).

## Common Usage Patterns

### 1. Initial Reconnaissance
```bash
# Full cluster and cloud recon
kubeshadow recon

# Only Kubernetes recon
kubeshadow recon --k8s-only

# Only cloud recon
kubeshadow recon --cloud-only

# Stealth mode recon
kubeshadow recon --stealth
```

### 2. Privilege Escalation
```bash
# RBAC escalation
kubeshadow rbac-escalate --kubeconfig ~/.kube/config

# Cloud privilege escalation
kubeshadow cloud-elevator

# Assume role abuse
kubeshadow assume-role-abuse --role-arn arn:aws:iam::123456789012:role/target-role
```

### 3. Pod Manipulation
```bash
# Sidecar injection
kubeshadow sidecarinject --mode api --pod target-pod --namespace default

# ETCD injection
kubeshadow etcdinject --endpoint https://etcd:2379 --cert cert.pem --key key.pem --ca ca.pem

# Kubelet exploitation
kubeshadow kubelet-jack --node-ip 10.0.0.10 --port 10250
```

### 4. Stealth Operations
```bash
# Audit bypass testing
kubeshadow audit-bypass --kubeconfig ~/.kube/config

# DNS cache poisoning
kubeshadow dns-poison --target-service kube-dns

# Cleanup operations
kubeshadow cleanup --namespace default --resource-type pods
```

### 5. Out-of-Cluster Attacks
```bash
# Registry backdoor
kubeshadow registry-backdoor --registry-url https://registry.example.com --image nginx:latest
```

## Security Considerations

1. **Legal and Ethical Use**
   - Only use on systems you own or have explicit permission to test
   - Follow responsible disclosure practices
   - Document all testing activities
   - Obtain necessary authorization before testing

2. **Safe Testing Practices**
   - Use in isolated test environments
   - Avoid production systems
   - Implement proper logging and monitoring
   - Clean up after testing
   - Use appropriate RBAC permissions
   - Follow least privilege principle

3. **Required Permissions**

   > ⚠️ **Warning**: While some modules may work with minimal permissions, others require elevated access. Always use the minimum required permissions for your testing needs.

   ### Minimum Required Permissions
   - **Read Access** (Basic Reconnaissance):
     - `get`, `list` on `pods`, `services`, `nodes`, `namespaces`
     - `get`, `list` on `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`
     - `get`, `list` on `serviceaccounts`

   ### Module-Specific Requirements
   - **Cluster Exploitation Modules**:
     - `etcdinject`: Direct etcd access or `update` on `pods`
     - `kubelet-jack`: Node network access and kubelet API access
     - `sidecarinject`: `update` on `pods` in target namespace
     - `rbac-escalate`: `get`, `list` on `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`
     - `namespace-pivot`: `get`, `list` on `serviceaccounts`, `secrets` in target namespaces

   - **Cloud Exploitation Modules**:
     - `metadata-hijack`: Pod execution permissions
     - `cloud-elevator`: Cloud provider IAM permissions
     - `assume-role-abuse`: AWS STS permissions

   - **Stealth Operations**:
     - `audit-bypass`: `get` on `auditpolicies`
     - `dns-poison`: Network access to DNS service
     - `cleanup`: `delete` on target resources

   - **Out-of-Cluster Operations**:
     - `registry-backdoor`: Container registry credentials

   ### Recommended Setup
   - Create dedicated service accounts for testing
   - Use role-based access control (RBAC)
   - Implement network policies
   - Enable audit logging
   - Use separate namespaces for testing

## Project Structure

```
KubeShadow/
├── modules/                 # Core exploitation modules
│   ├── cluster_exploit/    # Cluster exploitation tools
│   ├── multi_cloud/        # Cloud provider exploitation
│   ├── out_cluster/        # External infrastructure attacks
│   ├── recon/             # Reconnaissance tools
│   └── stealth/           # Stealth operation tools
├── pkg/                    # Supporting packages
│   ├── banner/            # CLI banner utilities
│   ├── config/            # Configuration management
│   ├── errors/            # Error handling
│   ├── etcd/              # ETCD client utilities
│   ├── k8s/               # Kubernetes client utilities
│   ├── kubelet/           # Kubelet API utilities
│   ├── logger/            # Logging utilities
│   ├── modules/           # Module interfaces
│   ├── plugins/           # Plugin system
│   ├── recon/             # Reconnaissance utilities
│   ├── registry/          # Module registry
│   ├── testutil/          # Testing utilities
│   ├── types/             # Common types
│   └── utils/             # General utilities
├── docs/                  # Documentation
│   ├── modules/          # Module-specific documentation
│   └── architecture.md   # Architecture overview
├── examples/             # Usage examples
│   └── sidecar-config.json  # Example configurations
├── resources/           # Resource files
│   ├── configs/        # Configuration templates
│   └── templates/      # Template files
└── .github/            # GitHub workflows and templates
```

## Documentation

Detailed documentation is available in the `docs/` directory:
- [Architecture Overview](docs/architecture.md)
- [Module Documentation](docs/modules/)
- [Troubleshooting Guide](docs/troubleshooting.md)
- [Contributing Guide](CONTRIBUTING.md)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes.
