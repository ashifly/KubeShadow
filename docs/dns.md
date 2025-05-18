# DNS Cache Poisoning Module

The `dns-poison` module tests for DNS cache poisoning vulnerabilities in Kubernetes clusters.

## Usage
```bash
kubeshadow dns-poison [--kubeconfig PATH]
```

## Features
- Analyzes CoreDNS configuration for weaknesses
- Tests DNS resolution for potential poisoning
- Identifies vulnerable DNS configurations
- Simulates DNS spoofing attacks

## Attack Vectors

1. **CoreDNS Misconfigurations**
   - Rewrite rules
   - Template plugins
   - Fallthrough settings

2. **Service Discovery Attacks**
   - Service name shadowing
   - Cross-namespace resolution
   - Wildcard certificate abuse

3. **Cloud Metadata Access**
   - Internal DNS resolution
   - Metadata service endpoints
   - Cloud provider APIs

## Examples
```bash
# Basic DNS analysis
kubeshadow dns-poison

# With specific kubeconfig
kubeshadow dns-poison --kubeconfig ~/.kube/config
```

## Security Recommendations

1. CoreDNS Configuration:
   - Limit rewrite rules
   - Avoid template plugins
   - Restrict fallthrough

2. Network Policies:
   - Implement DNS policy
   - Restrict cross-namespace access
   - Block external DNS

3. Monitoring:
   - Enable DNS logging
   - Monitor resolution patterns
   - Alert on suspicious queries

## Common Vulnerabilities

1. **Misconfigured CoreDNS**
   - Overly permissive rewrite rules
   - Unsafe template configurations
   - Unrestricted fallthrough

2. **Service Discovery**
   - Missing network policies
   - Cross-namespace access
   - Wildcard resolution

3. **Cloud Integration**
   - Metadata service access
   - Internal DNS exposure
   - Cloud API access