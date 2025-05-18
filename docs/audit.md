# Audit Policy Bypass Module

The `audit-bypass` module analyzes and tests Kubernetes audit policy configurations for potential bypass vectors.

## Usage
```bash
kubeshadow audit-bypass --kubeconfig PATH [--audit-policy PATH]
```

### Required Flags
- `--kubeconfig`: Path to kubeconfig file
- `--audit-policy`: (Optional) Path to audit policy file for analysis

## Features
- Analyzes audit policy rules for weaknesses
- Tests stealthy operation patterns
- Identifies audit blind spots
- Simulates audit bypass techniques

## Attack Vectors

1. **Audit Level Manipulation**
   - Metadata-only logging
   - Missing verb coverage
   - Incomplete resource tracking

2. **Stealthy Operations**
   - Alternative API verbs
   - Subresource access
   - Proxy requests

3. **RBAC Combinations**
   - ServiceAccount tokens
   - Unauthenticated access
   - Cross-namespace operations

## Examples
```bash
# Basic audit analysis
kubeshadow audit-bypass --kubeconfig ~/.kube/config

# With audit policy file
kubeshadow audit-bypass --kubeconfig ~/.kube/config --audit-policy /path/to/audit-policy.yaml
```

## Security Recommendations

1. Audit Policy Configuration:
   - Use appropriate audit levels
   - Cover all critical operations
   - Include all resource types

2. RBAC Controls:
   - Limit ServiceAccount permissions
   - Block unauthenticated access
   - Implement namespace isolation

3. Monitoring:
   - Enable comprehensive logging
   - Monitor for bypass patterns
   - Alert on suspicious activity

## Common Weaknesses

1. **Insufficient Logging**
   - Missing operation types
   - Metadata-only rules
   - Incomplete resource coverage

2. **RBAC Issues**
   - Overly permissive bindings
   - Unauthenticated access
   - Missing namespace restrictions

3. **Operational Gaps**
   - Subresource blind spots
   - Proxy request logging
   - Aggregated API servers