# KubeShadow Documentation

KubeShadow is a Kubernetes security testing and exploitation toolkit designed for red team operations and security assessments.

## Module Categories

KubeShadow is organized into the following module categories:

### 1. Cluster Exploitation Modules (`cluster_exploit/`)
- [ETCD Injection](modules/cluster_exploit/etcd_inject.md) - Direct pod injection via etcd
- [Kubelet Exploitation](modules/cluster_exploit/kubelet_jack.md) - Kubelet API exploitation
- [Sidecar Injection](modules/cluster_exploit/sidecar_inject.md) - Pod sidecar container injection
- [RBAC Escalation](modules/cluster_exploit/rbac_escalate.md) - RBAC privilege escalation
- [Namespace Pivot](modules/cluster_exploit/namespace_pivot.md) - Cross-namespace access

### 2. Cloud Exploitation Modules (`multi_cloud/`)
- [Metadata Hijacking](modules/multi_cloud/metadata_hijack.md) - Cloud metadata service exploitation
- [Cloud Privilege Escalation](modules/multi_cloud/cloud_elevator.md) - Cloud IAM privilege escalation

### 3. Reconnaissance Module (`recon/`)
- [Cluster Reconnaissance](modules/recon/cluster_recon.md) - Kubernetes cluster information gathering
- [Cloud Reconnaissance](modules/recon/cloud_recon.md) - Cloud provider metadata discovery

### 4. Stealth Modules (`stealth/`)
- [Audit Bypass](modules/stealth/audit_bypass.md) - Audit policy bypass testing
- [DNS Cache Poisoning](modules/stealth/dns_poison.md) - DNS cache poisoning attacks

## Quick Start

1. Install KubeShadow:
```bash
go get github.com/ashifly/KubeShadow
```

2. Basic reconnaissance:
```bash
kubeshadow recon --kubeconfig ~/.kube/config
```

3. View available commands:
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
```

### 2. Privilege Escalation
```bash
# RBAC escalation
kubeshadow rbac-escalate --kubeconfig ~/.kube/config

# Cloud privilege escalation
kubeshadow cloud-elevator
```

### 3. Pod Manipulation
```bash
# Sidecar injection
kubeshadow sidecarinject --mode api --pod target-pod --namespace default

# ETCD injection
kubeshadow etcdinject --endpoint https://etcd:2379 --cert cert.pem --key key.pem --ca ca.pem
```

## Security Considerations

1. **Legal and Ethical Use**
   - Only use on systems you own or have explicit permission to test
   - Follow responsible disclosure practices
   - Document all testing activities

2. **Safe Testing Practices**
   - Use in isolated test environments
   - Avoid production systems
   - Implement proper logging and monitoring
   - Clean up after testing

3. **Required Permissions**
   - Cluster admin or equivalent for full functionality
   - Service account with appropriate RBAC
   - Cloud provider credentials for cloud modules

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request
4. Follow the code style guidelines
5. Add appropriate tests
6. Update documentation

## License

This project is licensed under the MIT License - see the LICENSE file for details. 