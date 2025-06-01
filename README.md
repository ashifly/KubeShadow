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

#### 1. Cluster Exploitation (`modules/cluster_exploit/`)
- **ETCD Injection**: Direct pod injection via etcd
- **Kubelet Exploitation**: Kubelet API exploitation and hijacking
- **Sidecar Injection**: Pod sidecar container injection
- **RBAC Escalation**: RBAC privilege escalation and permission analysis
- **Namespace Pivot**: Cross-namespace access and privilege movement

#### 2. Cloud Exploitation (`modules/multi_cloud/`)
- **Metadata Hijacking**: Cloud metadata service exploitation
- **Cloud Privilege Escalation**: Cloud IAM privilege escalation
- **Assume Role Abuse**: Cloud role assumption and token abuse
- **Cloud Elevator**: Automated cloud privilege escalation paths

#### 3. Reconnaissance (`modules/recon/`)
- **Cluster Reconnaissance**: Comprehensive Kubernetes cluster information gathering
  - RBAC analysis
  - Network policy enumeration
  - Service account discovery
  - Pod security context analysis
  - Node information gathering

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

# Build from source
git clone https://github.com/ashifly/KubeShadow
cd KubeShadow
go build -o kubeshadow
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