# Cluster Reconnaissance Module

The cluster reconnaissance module performs comprehensive information gathering about Kubernetes clusters, including RBAC, network policies, service accounts, and more.

## Overview

This module helps identify:
- Cluster configuration and version information
- RBAC permissions and role bindings
- Network policies and service mesh configurations
- Service account tokens and secrets
- Pod security policies and security contexts
- Exposed services and endpoints
- Node information and taints
- Namespace configurations

## Usage

### Basic Usage

```bash
# Full cluster reconnaissance
kubeshadow recon --kubeconfig ~/.kube/config

# Stealth mode (minimal API calls)
kubeshadow recon --stealth

# Only Kubernetes recon (no cloud)
kubeshadow recon --k8s-only
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig` | Path to kubeconfig file | `~/.kube/config` |
| `--stealth` | Enable stealth mode (minimal API calls) | `true` |
| `--k8s-only` | Perform only Kubernetes API recon | `false` |
| `--cloud-only` | Perform only cloud metadata recon | `false` |

## Output

The module provides detailed information about:

### 1. Cluster Information
- Kubernetes version
- API server endpoints
- Control plane components
- Node information
- Resource quotas and limits

### 2. RBAC Analysis
- ClusterRoles and Roles
- RoleBindings and ClusterRoleBindings
- Service account permissions
- Privilege escalation paths
- Dangerous permissions

### 3. Network Security
- Network policies
- Service mesh configurations
- Ingress controllers
- Load balancers
- Exposed services

### 4. Pod Security
- Pod security policies
- Security contexts
- Privileged containers
- Host path mounts
- Capabilities

### 5. Secrets and Tokens
- Service account tokens
- Secrets in namespaces
- Image pull secrets
- TLS certificates
- OAuth tokens

## Examples

### 1. Basic Reconnaissance
```bash
kubeshadow recon
```
Output:
```
[+] Starting Kubernetes Recon...
[+] Cluster Version: v1.24.0
[+] API Server: https://10.0.0.1:6443
[+] Nodes: 3
[+] Namespaces: 5
[+] RBAC Analysis:
    - Found 12 ClusterRoles
    - Found 8 ClusterRoleBindings
    - 3 ServiceAccounts with cluster-admin
[+] Network Policies:
    - 2 policies in default namespace
    - 1 policy in kube-system
[+] Security Contexts:
    - 5 pods with privileged access
    - 3 pods with host path mounts
```

### 2. Stealth Mode
```bash
kubeshadow recon --stealth
```
Output:
```
[+] Starting Stealth Kubernetes Recon...
[+] Basic Cluster Info:
    - Version: v1.24.0
    - Nodes: 3
[+] Critical Findings:
    - 2 privileged pods
    - 1 exposed service
```

### 3. Focused Reconnaissance
```bash
# Only check RBAC
kubeshadow recon --k8s-only --focus rbac

# Only check network policies
kubeshadow recon --k8s-only --focus network
```

## Security Considerations

1. **API Server Load**
   - Stealth mode reduces API server load
   - Use appropriate timeouts
   - Implement rate limiting

2. **Detection Avoidance**
   - Minimize API calls in stealth mode
   - Use appropriate user agents
   - Avoid suspicious patterns

3. **Data Handling**
   - Don't store sensitive data
   - Clean up temporary files
   - Use secure output formats

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   Error: failed to get cluster info: pods is forbidden
   ```
   Solution: Ensure proper RBAC permissions

2. **Connection Timeout**
   ```bash
   Error: failed to connect to API server: timeout
   ```
   Solution: Check network connectivity and API server health

3. **Invalid Kubeconfig**
   ```bash
   Error: invalid kubeconfig: context not found
   ```
   Solution: Verify kubeconfig path and context

## Best Practices

1. **Start with Stealth Mode**
   - Use `--stealth` for initial reconnaissance
   - Minimize detection risk
   - Gather basic information first

2. **Progressive Reconnaissance**
   - Start with basic cluster info
   - Move to RBAC analysis
   - Then check network policies
   - Finally examine pod security

3. **Documentation**
   - Document all findings
   - Note potential security issues
   - Track privilege escalation paths

4. **Clean Up**
   - Remove temporary files
   - Clear command history
   - Log out of service accounts

## API Reference

### ReconConfig
```go
type ReconConfig struct {
    Kubeconfig string
    Stealth    bool
    K8sOnly    bool
    CloudOnly  bool
}
```

### Methods
- `K8sRecon(ctx, kubeconfig, stealth)`: Performs Kubernetes reconnaissance
- `CloudRecon(ctx, stealth)`: Performs cloud provider reconnaissance
- `Validate()`: Validates the configuration
- `Cleanup()`: Performs cleanup operations 