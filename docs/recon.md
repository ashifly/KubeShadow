# Reconnaissance Module

The reconnaissance module helps gather information about Kubernetes clusters and cloud provider configurations for security assessment.

## Overview

This module performs:
- Kubernetes cluster reconnaissance
- Cloud provider metadata discovery
- RBAC permission analysis
- Network policy enumeration
- Service account token discovery

## Usage Examples

### Kubernetes Cluster Recon
```bash
# Basic cluster information
./kubeshadow recon cluster

# Detailed node analysis
./kubeshadow recon nodes --detailed

# Service account enumeration
./kubeshadow recon serviceaccounts --namespace=kube-system
```

### Cloud Provider Recon
```bash
# Auto-detect and scan cloud metadata
./kubeshadow recon cloud

# Specific cloud provider scan
./kubeshadow recon cloud --provider=aws
```

### RBAC Analysis
```bash
# Check current permissions
./kubeshadow recon rbac --current-sa

# Analyze specific service account
./kubeshadow recon rbac \
    --namespace=default \
    --serviceaccount=target-sa
```

## Parameters

### Common Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--namespace` | Target namespace | default |
| `--output` | Output format (json/yaml) | yaml |
| `--detailed` | Include detailed information | false |

### Cloud Recon Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--provider` | Cloud provider (aws/gcp/azure) | auto |
| `--metadata-endpoint` | Custom metadata endpoint | - |
| `--timeout` | Request timeout | 5s |

### RBAC Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--serviceaccount` | Target service account | - |
| `--current-sa` | Use current service account | false |
| `--check-escalation` | Check for privilege escalation | false |

## Requirements

- Access to cluster API server
- Service account token or kubeconfig
- Network access to:
  - Kubernetes API
  - Cloud metadata endpoints
  - Node endpoints

## Security Considerations

1. Detection Risk:
   - Multiple API requests may trigger alerts
   - Cloud metadata access may be monitored
   - Failed RBAC checks are logged

2. Rate Limiting:
   - Respect API rate limits
   - Use appropriate timeouts
   - Implement backoff for retries

## Output Examples

### Cluster Information
```yaml
cluster:
  version: v1.24.0
  nodes: 5
  pods: 120
  namespaces: 8
  apiServer: https://10.0.0.1:6443
  networkPlugin: calico
```

### RBAC Analysis
```yaml
permissions:
  allowed:
    - pods: [get, list]
    - services: [get, list]
  denied:
    - pods: [create, delete]
    - secrets: [get, list]
  risky:
    - configmaps: [create] # Potential for config injection
```

## Troubleshooting

### Common Issues

1. API Access:
   ```
   ❌ failed to connect to API server
   ```
   - Solution: Check kubeconfig
   - Verify network connectivity
   - Validate service account token

2. Cloud Metadata:
   ```
   ❌ metadata endpoint not accessible
   ```
   - Solution: Check cloud provider
   - Verify instance has metadata access
   - Check network policies

3. RBAC Checks:
   ```
   ❌ permission denied listing secrets
   ```
   - Solution: Verify service account permissions
   - Check namespace access
   - Review cluster roles 