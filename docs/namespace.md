# Namespace Pivoting Module

The `namespace-pivot` module identifies and tests for namespace isolation weaknesses in Kubernetes clusters.

## Usage
```bash
kubeshadow namespace-pivot [--kubeconfig PATH]
```

## Features
- Enumerates namespace permissions
- Identifies pivot opportunities
- Tests service account tokens
- Analyzes RBAC bindings

## Attack Vectors

1. **Service Account Exploitation**
   - Token extraction
   - Permission analysis
   - Cross-namespace access

2. **RBAC Misconfigurations**
   - RoleBinding analysis
   - ClusterRoleBinding review
   - Permission aggregation

3. **Resource Access**
   - Secret enumeration
   - ConfigMap access
   - Pod execution

## Examples
```bash
# Basic namespace analysis
kubeshadow namespace-pivot --kubeconfig ~/.kube/config
```

## Security Recommendations

1. Service Account Security:
   - Limit token access
   - Use minimal permissions
   - Enable token bound service accounts

2. RBAC Configuration:
   - Implement namespace isolation
   - Avoid cluster-wide roles
   - Regular binding review

3. Resource Protection:
   - Encrypt secrets
   - Use network policies
   - Enable admission controls

## Common Vulnerabilities

1. **Service Account Issues**
   - Exposed tokens
   - Excessive permissions
   - Cross-namespace access

2. **RBAC Problems**
   - Overly permissive roles
   - Unnecessary cluster roles
   - Missing namespace restrictions

3. **Resource Exposure**
   - Unencrypted secrets
   - Shared resources
   - Missing network policies

## Best Practices

1. **Namespace Isolation**
   - Use network policies
   - Implement resource quotas
   - Restrict service account permissions

2. **Access Control**
   - Regular RBAC audits
   - Minimal privilege principle
   - Token rotation

3. **Monitoring**
   - Track cross-namespace access
   - Monitor service account usage
   - Alert on suspicious activity