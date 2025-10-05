# K01 - Insecure Workload Configurations

## Overview

The K01 module is a comprehensive security scanner for Kubernetes workloads that detects dangerous security contexts, hostPath/hostNetwork configurations, privileged containers, elevated capabilities, and unsafe PodSecurity levels.

## Features

### 🔍 Detector
- Scans all workload types: Pods, Deployments, StatefulSets, DaemonSets
- Detects dangerous security contexts:
  - `securityContext.privileged: true`
  - `runAsUser: 0` (root user)
  - `allowPrivilegeEscalation: true`
  - `runAsNonRoot: false`
- Identifies host exposure:
  - `hostNetwork: true`
  - `hostPID: true`
  - `hostIPC: true`
  - Dangerous `hostPath` mounts
- Analyzes capabilities and image policies

### 📈 Analyzer
- **CVSS-style risk scoring**: Each vulnerability has a CVSS score
- **Service account analysis**: Tracks SA privileges
- **Namespace sensitivity**: Detects sensitive namespaces
- **Host exposure scoring**: Higher risk for host-exposed workloads
- **Severity classification**: Critical, High, Medium, Low

### 🧪 Simulator (Lab Mode)
- Non-destructive testing with `--lab` flag
- Creates benign helper pods with `--simulate` flag
- Demonstrates "what would be possible" without harm
- Automatic cleanup of simulation resources

### 📄 Output Formats
- **JSON**: Complete findings in `insecure_workloads.json`
- **CSV**: Structured data for analysis
- **OPA Policy**: Complete admission controller policies
- **Text Reports**: Human-readable summaries

## Usage

### Basic Commands

```bash
# Basic scan
kubeshadow workload-config

# Scan with custom output
kubeshadow workload-config --output ./findings.json

# Lab simulation
kubeshadow workload-config --lab --simulate

# Filter by severity
kubeshadow workload-config --severity critical,high

# Scan specific namespace
kubeshadow workload-config --namespace kube-system

# Show only remediation
kubeshadow workload-config --remediation-only
```

### Command Options

| Flag | Description | Default |
|------|-------------|---------|
| `--output, -o` | Output file path for findings | `./insecure_workloads.json` |
| `--lab` | Enable lab mode for non-destructive testing | `false` |
| `--simulate` | Run simulation to demonstrate potential impact | `false` |
| `--kubeconfig` | Path to kubeconfig file | `~/.kube/config` |
| `--namespace, -n` | Scan specific namespace | All namespaces |
| `--severity` | Filter by severity levels | All severities |
| `--remediation-only` | Show only remediation suggestions | `false` |

## Vulnerability Detection

### Critical Vulnerabilities (CVSS 9.0+)
- **Privileged containers**: `securityContext.privileged: true`
- **Dangerous hostPath mounts**: `/etc`, `/root`, `/var/run`, etc.
- **Excessive capabilities**: `ALL` capabilities granted

### High Vulnerabilities (CVSS 7.0-8.9)
- **Root user**: `runAsUser: 0` or `runAsNonRoot: false`
- **Privilege escalation**: `allowPrivilegeEscalation: true`
- **Host namespaces**: `hostNetwork`, `hostPID`, `hostIPC`

### Medium Vulnerabilities (CVSS 4.0-6.9)
- **Image pull policy**: `imagePullPolicy: Always`
- **Writable root filesystem**: `readOnlyRootFilesystem: false`

### Low Vulnerabilities (CVSS <4.0)
- **Minor misconfigurations**: Non-critical security issues

## Risk Scoring

The module uses a CVSS-style scoring system:

```go
// Example risk calculation
riskScore := 0.0

// Privileged container (Critical)
if container.SecurityContext.Privileged {
    riskScore += 9.8
}

// Root user (High)
if container.SecurityContext.RunAsUser == 0 {
    riskScore += 7.5
}

// Host network (High)
if pod.Spec.HostNetwork {
    riskScore += 7.2
}
```

## Output Formats

### JSON Structure

```json
{
  "scanMetadata": {
    "scanId": "kubeshadow-workload-1234567890",
    "timestamp": "2025-01-10T21:39:00Z",
    "version": "1.0.0",
    "scanner": "KubeShadow K01",
    "clusterName": "production-cluster",
    "namespaces": ["default", "kube-system"]
  },
  "summary": {
    "totalWorkloads": 15,
    "vulnerableWorkloads": 3,
    "totalVulnerabilities": 8,
    "averageRiskScore": 6.2,
    "maxRiskScore": 9.8,
    "severityBreakdown": {
      "critical": 1,
      "high": 2,
      "medium": 0,
      "low": 0
    }
  },
  "findings": [
    {
      "workloadName": "vulnerable-app",
      "workloadType": "Deployment",
      "namespace": "default",
      "severity": "CRITICAL",
      "riskScore": 9.8,
      "vulnerabilities": [
        {
          "type": "privileged",
          "description": "Container 'app' is running in privileged mode",
          "severity": "CRITICAL",
          "cvss": 9.8
        }
      ],
      "remediation": {
        "description": "Apply Pod Security Standards and OPA/Gatekeeper policies",
        "opaPolicy": "package kubernetes.admission\n\ndeny[msg] { ... }",
        "kubectlApply": "kubectl apply -f - <<EOF\n..."
      }
    }
  ]
}
```

### CSV Export

```csv
WorkloadName,WorkloadType,Namespace,Severity,RiskScore,HostExposure,ServiceAccount,NamespaceSensitive,VulnerabilityCount
vulnerable-app,Deployment,default,CRITICAL,9.8,true,default,false,1
```

## Remediation

### OPA Policy Example

```rego
package kubernetes.admission

# Deny privileged containers
deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.operation == "CREATE"
    input.request.object.spec.containers[_].securityContext.privileged == true
    msg := "Privileged containers are not allowed"
}

# Deny root user
deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.operation == "CREATE"
    input.request.object.spec.securityContext.runAsUser == 0
    msg := "Running as root user is not allowed"
}
```

### Gatekeeper Policy Example

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8spspsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sPSPSecurityContext
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspsecuritycontext
        
        violation[{"msg": msg}] {
          input.review.object.spec.containers[_].securityContext.privileged == true
          msg := "Privileged containers are not allowed"
        }
```

### Pod Security Standards

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## Lab Simulation

The lab simulation feature creates a benign helper pod to demonstrate secure configurations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubeshadow-workload-simulator
  namespace: default
spec:
  containers:
  - name: simulator
    image: alpine:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
    command: ["sh", "-c"]
    args:
    - echo '🔍 KubeShadow Workload Simulator'
    - echo '📊 Demonstrating secure configuration'
    - sleep 30
    - echo '✅ Simulation completed'
```

## Integration

### Dashboard Integration

```bash
# Run with dashboard
kubeshadow workload-config --dashboard

# Custom dashboard port
kubeshadow workload-config --dashboard --dashboard-port 8080
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Scan workloads
  run: |
    kubeshadow workload-config --output ./security-findings.json
    
- name: Upload findings
  uses: actions/upload-artifact@v3
  with:
    name: security-findings
    path: ./security-findings.json
```

## Examples

### Scan Production Cluster

```bash
# Scan all workloads
kubeshadow workload-config --kubeconfig ~/.kube/prod-config

# Focus on critical issues
kubeshadow workload-config --severity critical,high --namespace kube-system

# Generate remediation policies
kubeshadow workload-config --remediation-only --output ./remediation-policies.json
```

### Lab Testing

```bash
# Run lab simulation
kubeshadow workload-config --lab --simulate

# Test specific namespace
kubeshadow workload-config --lab --namespace test-namespace --simulate
```

### Export Results

```bash
# JSON output
kubeshadow workload-config --output ./workload-security-report.json

# CSV export
kubeshadow workload-config --output ./workload-security-report.csv
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure proper RBAC permissions
2. **Kubeconfig not found**: Specify correct kubeconfig path
3. **Namespace access**: Verify namespace permissions

### Debug Mode

```bash
# Enable verbose logging
kubeshadow workload-config --kubeconfig ~/.kube/config -v
```

## Security Considerations

- **Lab mode only**: Simulation features are safe and non-destructive
- **Read-only scanning**: No modifications to cluster resources
- **Minimal permissions**: Only requires read access to workloads
- **Secure defaults**: Follows security best practices

## Contributing

To extend the K01 module:

1. Add new vulnerability types in `analyzePodSpec()`
2. Update risk scoring in the analyzer
3. Add new output formats in `json_output.go`
4. Extend remediation suggestions

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [CVSS Scoring](https://www.first.org/cvss/)
- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
