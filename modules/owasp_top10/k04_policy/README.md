# K04 - Lack of Centralized Policy Enforcement

## Overview

K04 focuses on detecting missing centralized policy enforcement mechanisms in Kubernetes clusters. This module identifies gaps in policy coverage and provides recommendations for implementing comprehensive policy enforcement.

## Features

### 🔍 Detector
- Checks for presence of policy engines:
  - **Gatekeeper**: OPA-based policy engine with constraints
  - **OPA**: Open Policy Agent with custom policies
  - **Kyverno**: Kubernetes-native policy engine
- Validates enforcement levels and policy configurations
- Lists existing policies and exemptions
- Detects admission webhooks and their configurations

### 📊 Analyzer
- Identifies namespaces not covered by policies
- Finds namespaces with many exemptions
- Analyzes resource type coverage gaps
- Calculates overall policy coverage score
- Identifies missing standard policies

### 🧪 Simulator
- Runs policy evaluation engine offline
- Tests sample manifests against policies
- Shows what would be blocked by policies
- Demonstrates policy enforcement scenarios
- Generates policy test suites

### 📄 Outputs
- `policy_coverage.json` - Complete policy coverage analysis
- Policy gaps and missing enforcement mechanisms
- Recommended standard policies (pod-security, no-hostpath, no-privileged, image-signing)
- Implementation manifests and remediation steps

## Usage

### Basic Scan
```bash
kubeshadow owasp k04
```

### Namespace-Specific Scan
```bash
kubeshadow owasp k04 --namespace kube-system
```

### Lab Simulation
```bash
kubeshadow owasp k04 --lab --simulate
```

### Apply Lab Environment
```bash
kubeshadow owasp k04 --lab --apply
```

### Filter by Severity
```bash
kubeshadow owasp k04 --severity critical,high
```

## Policy Engines Detection

### Gatekeeper
- Detects Gatekeeper installation in `gatekeeper-system` namespace
- Analyzes constraints and constraint templates
- Checks enforcement modes (warn, deny, dryrun)
- Identifies constraint violations

### OPA
- Detects OPA installation and configuration
- Lists OPA policies and their status
- Checks policy enablement
- Analyzes policy coverage

### Kyverno
- Detects Kyverno installation in `kyverno` namespace
- Analyzes policies and cluster policies
- Checks validation modes (enforce, audit, warn)
- Identifies background validation settings

## Policy Coverage Analysis

### Namespace Coverage
- **Pod Security Standards**: Checks for PSA labels
- **Policy Exemptions**: Identifies exempted namespaces
- **Coverage Score**: Calculates policy coverage percentage
- **Risk Level**: Assesses security risk based on coverage

### Resource Type Coverage
- **Pods**: Security contexts, resource limits, host access
- **Services**: External IPs, network policies
- **Secrets**: Encryption, rotation policies
- **Deployments**: Resource quotas, security policies

## Standard Policies

### Pod Security Standards
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### No HostPath Policy
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-hostpath
spec:
  validationFailureAction: enforce
  background: true
  rules:
  - name: check-hostpath
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "HostPath volumes are not allowed"
      pattern:
        spec:
          =(volumes):
          - X(hostPath): "null"
```

### No Privileged Policy
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowPrivileged
      validation:
        properties:
          exemptImages:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowprivileged
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged
          not exempt_image(container.image)
          msg := sprintf("Privileged container is not allowed: %v", [container.name])
        }
        
        exempt_image(image) {
          exempt_images := object.get(input.parameters, "exemptImages", [])
          exempt_images[_] == image
        }
```

### Mandatory Image Signing
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: enforce
  background: true
  rules:
  - name: check-image-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must be signed"
      pattern:
        spec:
          containers:
          - name: "*"
            image: "cosign-verified:*"
```

## Lab Environment

The lab creates a controlled environment with:

- Namespace with Pod Security Standards enabled
- Resource quotas for resource management
- Network policies for traffic control
- Policy test scenarios

### Lab Commands
```bash
# Create lab environment
kubeshadow owasp k04 --lab --apply

# Run policy simulation
kubeshadow owasp k04 --lab --simulate

# Clean up (manual)
kubectl delete namespace policy-lab
```

## Policy Test Suite

The module generates a comprehensive test suite:

```bash
#!/bin/bash
# Policy Test Suite for Kubernetes

# Test 1: Pod Security Standards
echo "Testing privileged container rejection..."
kubectl apply -f privileged-pod.yaml || echo "✅ Correctly blocked"

# Test 2: Resource Limits
echo "Testing resource limit enforcement..."
kubectl apply -f no-limits-pod.yaml || echo "✅ Correctly blocked"

# Test 3: Network Policies
echo "Testing network policy enforcement..."
kubectl apply -f external-service.yaml || echo "✅ Correctly blocked"
```

## Output Format

### JSON Structure
```json
{
  "enforcement": {
    "gatekeeper": {
      "installed": true,
      "version": "3.14.0",
      "constraints": [...],
      "constraintTemplates": [...]
    },
    "opa": {
      "installed": false
    },
    "kyverno": {
      "installed": true,
      "version": "1.10.0",
      "policies": [...]
    },
    "admissionWebhooks": [...],
    "policyCoverage": {
      "namespaces": [...],
      "resourceTypes": [...],
      "coverageScore": 0.75
    }
  },
  "findings": [
    {
      "namespace": "default",
      "resourceType": "Namespace",
      "policyGap": "Insufficient policy coverage",
      "severity": "HIGH",
      "riskScore": 0.8,
      "description": "Namespace has low policy coverage",
      "recommendation": "Apply standard policies"
    }
  ]
}
```

## Security Considerations

- **Lab Mode Only**: Never use `--apply` in production
- **Read-Only Analysis**: Default mode is non-destructive
- **Privilege Requirements**: Requires cluster read permissions
- **Policy Sensitivity**: Policy data may contain sensitive configuration

## Integration

### CI/CD Pipeline
```yaml
- name: Policy Coverage Scan
  run: kubeshadow owasp k04 --output policy-report.json
```

### Monitoring
- Set up alerts for policy engine failures
- Monitor policy coverage metrics
- Track policy violations and exemptions

### Remediation Automation
- Use GitOps for policy deployment
- Implement policy testing in CI/CD
- Regular policy coverage audits
