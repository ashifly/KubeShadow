# RBAC Analysis Module

The RBAC analysis module helps identify and exploit RBAC misconfigurations in Kubernetes clusters.

## Overview

This module provides:
- RBAC permission analysis
- Privilege escalation path detection
- Service account token discovery
- Role and ClusterRole analysis
- RoleBinding and ClusterRoleBinding enumeration

## Usage Examples

### Permission Analysis
```bash
# Check current service account permissions
./kubeshadow rbac analyze --current-sa

# Analyze specific service account
./kubeshadow rbac analyze \
    --namespace=default \
    --serviceaccount=target-sa

# Find privilege escalation paths
./kubeshadow rbac escalate \
    --namespace=default \
    --serviceaccount=target-sa
```

### Role Analysis
```bash
# List dangerous roles
./kubeshadow rbac roles --dangerous

# Check specific role
./kubeshadow rbac roles \
    --namespace=default \
    --name=pod-admin \
    --check-bindings
```

### Token Discovery
```bash
# Find mounted service account tokens
./kubeshadow rbac tokens --mounted

# List all service account tokens
./kubeshadow rbac tokens --all-namespaces
```

## Parameters

### Common Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--namespace` | Target namespace | default |
| `--serviceaccount` | Service account name | - |
| `--output` | Output format (json/yaml) | yaml |

### Analysis Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--current-sa` | Use current service account | false |
| `--dangerous` | Show only dangerous permissions | false |
| `--check-bindings` | Include role binding analysis | false |

### Token Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--mounted` | Show only mounted tokens | false |
| `--all-namespaces` | Search in all namespaces | false |
| `--min-age` | Minimum token age | 0 |

## Requirements

- Access to Kubernetes API server
- Permissions to:
  - List roles and role bindings
  - Get service accounts
  - Access pod information (for token discovery)

## Security Considerations

1. Permission Levels:
   - Cluster-wide permissions
   - Namespace-scoped permissions
   - Aggregated roles

2. High-Risk Permissions:
   ```yaml
   - pods/exec
   - pods/attach
   - secrets
   - serviceaccounts/token
   - roles/bind
   ```

3. Detection Risk:
   - RBAC queries are logged
   - Token access is audited
   - Failed permission checks alert

## Output Examples

### Permission Analysis
```yaml
analysis:
  dangerous_permissions:
    - resource: pods/exec
      verbs: [create]
      risk: "Command execution in pods"
    - resource: secrets
      verbs: [get, list]
      risk: "Sensitive data exposure"
  
  escalation_paths:
    - via: roles
      steps:
        - create pod with hostPath
        - mount node filesystem
        - access node credentials
```

### Token Discovery
```yaml
tokens:
  mounted:
    - namespace: default
      pod: web-server
      serviceaccount: admin-sa
      path: /var/run/secrets/kubernetes.io/serviceaccount
  
  available:
    - namespace: kube-system
      name: cluster-admin-token-xyz
      age: 90d
      permissions: cluster-admin
```

## Troubleshooting

### Common Issues

1. Permission Denied:
   ```
   ❌ failed to list roles: forbidden
   ```
   - Solution: Check RBAC permissions
   - Verify namespace access
   - Use correct service account

2. Token Access:
   ```
   ❌ unable to read service account token
   ```
   - Solution: Check mount paths
   - Verify token exists
   - Check file permissions

3. Analysis Errors:
   ```
   ❌ failed to check bindings
   ```
   - Solution: Verify role exists
   - Check binding permissions
   - Validate namespace access 