# K05 - Inadequate Logging and Monitoring

## Overview

K05 addresses the critical security risk of inadequate logging and monitoring in Kubernetes environments. This module helps identify gaps in telemetry infrastructure, audit logging, eBPF-based security monitoring, and SIEM integration.

## Features

### 🔍 **Detection Capabilities**
- **Kubernetes Audit Logging**: Detects if audit logging is enabled and configured properly
- **eBPF Security Monitoring**: Identifies presence of Falco, Tetragon, and other eBPF-based tools
- **SIEM Integration**: Checks for log forwarding to SIEM solutions (Splunk, ELK, QRadar, etc.)
- **Log Retention**: Analyzes log retention policies and rotation configurations
- **Cloud Provider Integration**: Detects integration with AWS CloudWatch, GCP Stackdriver, Azure Monitor

### 📊 **Analysis Features**
- **Coverage Scoring**: Calculates overall telemetry coverage percentage
- **Retention Analysis**: Evaluates log retention policies and storage efficiency
- **Risk Assessment**: Assigns risk scores to identified gaps
- **Compliance Mapping**: Maps findings to security frameworks (CIS, NIST, etc.)

### 🧪 **Simulation Features**
- **Synthetic Events**: Generates safe, non-destructive suspicious events for testing
- **Detection Pipeline Testing**: Validates detection capabilities without affecting production
- **Event Types**: Simulates privilege escalation, data exfiltration, container escapes, RBAC abuse
- **Performance Metrics**: Measures detection rates and response times

## Usage

### Basic Analysis
```bash
# Run complete telemetry analysis
kubeshadow owasp k05

# Analyze specific namespace
kubeshadow owasp k05 --namespace production

# Filter by severity
kubeshadow owasp k05 --severity critical
```

### Advanced Features
```bash
# Run detection pipeline simulation
kubeshadow owasp k05 --simulate

# Generate lab resources for testing
kubeshadow owasp k05 --lab

# Output in JSON format
kubeshadow owasp k05 --output json
```

### Lab Mode
```bash
# Generate comprehensive lab environment
kubeshadow owasp k05 --lab --simulate

# This creates:
# - k05-telemetry-lab/audit-policy.yaml
# - k05-telemetry-lab/falco-security-config.yaml
# - k05-telemetry-lab/tetragon-observability-config.yaml
# - k05-telemetry-lab/README.md
```

## Output Formats

### Table Output (Default)
```
🔍 K05 - Inadequate Logging and Monitoring Analysis
==================================================

📊 Summary:
  Total Findings: 5
  Critical: 2, High: 2, Medium: 1, Low: 0
  Coverage Score: 45.0%
  Retention Score: 30.0%
  Audit Enabled: false
  eBPF Enabled: false
  SIEM Integration: false

🚨 Findings:
  🔴 Critical: Kubernetes Audit Logging Disabled
    Description: No audit policy ConfigMap found. Audit logging is not configured.
    Resource: cluster/all
    Risk Score: 8.5
    Remediation: Enable Kubernetes audit logging by creating an audit policy ConfigMap and configuring the API server.

💡 Recommendations:
  1. Enable Kubernetes audit logging with comprehensive audit policy
  2. Deploy Falco with eBPF driver for runtime security monitoring
  3. Integrate with SIEM solution for centralized security monitoring
```

### JSON Output
```json
{
  "findings": [...],
  "summary": {
    "totalFindings": 5,
    "criticalCount": 2,
    "highCount": 2,
    "mediumCount": 1,
    "lowCount": 0,
    "coverageScore": 45.0,
    "retentionScore": 30.0,
    "auditEnabled": false,
    "ebpfEnabled": false,
    "siemIntegration": false
  },
  "recommendations": [...]
}
```

## Detection Methods

### 1. Audit Logging Detection
- **ConfigMap Analysis**: Searches for audit policy ConfigMaps
- **Webhook Configuration**: Checks for audit webhook configurations
- **API Server Configuration**: Analyzes API server audit settings
- **Log Forwarding**: Detects audit log forwarding mechanisms

### 2. eBPF Monitoring Detection
- **Falco Detection**: Identifies Falco deployments with eBPF driver
- **Tetragon Detection**: Finds Tetragon eBPF-based observability tools
- **Custom eBPF Tools**: Detects custom eBPF-based monitoring solutions
- **Driver Status**: Checks eBPF driver availability and configuration

### 3. SIEM Integration Detection
- **Log Forwarding Agents**: Identifies Fluentd, Fluent Bit, and similar tools
- **Cloud Provider Integration**: Detects AWS CloudWatch, GCP Stackdriver, Azure Monitor
- **SIEM Connectors**: Finds SIEM-specific log forwarding configurations
- **Network Connectivity**: Tests connectivity to SIEM endpoints

### 4. Retention Policy Analysis
- **Retention Configurations**: Analyzes log retention settings
- **Rotation Policies**: Checks log rotation configurations
- **Storage Efficiency**: Evaluates storage usage and cleanup policies
- **Compliance Requirements**: Maps retention to regulatory requirements

## Simulation Events

### Privilege Escalation Simulation
```json
{
  "id": "sim-pe-001",
  "type": "privilege-escalation",
  "severity": "high",
  "description": "Simulated privilege escalation attempt: User 'attacker' attempted to escalate privileges using sudo",
  "metadata": {
    "user": "attacker",
    "command": "sudo su -",
    "container": "privilege-test",
    "node": "worker-node-1",
    "risk_score": "8.5"
  }
}
```

### Data Exfiltration Simulation
```json
{
  "id": "sim-data-001",
  "type": "data-exfiltration",
  "severity": "critical",
  "description": "Simulated data exfiltration: Large amount of sensitive data being transferred out",
  "metadata": {
    "data_type": "pii",
    "data_size": "500MB",
    "dest_host": "external-server.com",
    "encryption": "none",
    "risk_score": "9.5"
  }
}
```

## Remediation Recommendations

### 1. Enable Kubernetes Audit Logging
```yaml
# audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["kube-system", "kube-public"]
  users: ["system:serviceaccount:kube-system:*"]
  verbs: ["get", "list", "watch"]
  resources: ["*"]
- level: RequestResponse
  namespaces: ["default", "production"]
  users: ["*"]
  verbs: ["create", "update", "patch", "delete"]
  resources: ["*"]
```

### 2. Deploy Falco with eBPF
```yaml
# falco-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-config
data:
  falco.yaml: |
    driver: ebpf
    rules_file: /etc/falco/falco_rules.yaml
    outputs:
      - stdout
      - file:/var/log/falco.log
    log_level: info
```

### 3. Configure SIEM Integration
```yaml
# siem-forwarder.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-forwarder
spec:
  template:
    spec:
      containers:
      - name: fluent-bit
        image: fluent/fluent-bit:latest
        env:
        - name: SIEM_ENDPOINT
          value: "https://siem.company.com/api/logs"
        - name: SIEM_TOKEN
          valueFrom:
            secretKeyRef:
              name: siem-credentials
              key: token
```

## Security Frameworks

### CIS Kubernetes Benchmark
- **Control 5.1.1**: Ensure that the cluster-admin role is only used where required
- **Control 5.1.2**: Minimize access to secrets
- **Control 5.1.3**: Minimize wildcard use in Roles and ClusterRoles

### NIST Cybersecurity Framework
- **PR.DS-1**: Data-at-rest is protected
- **PR.DS-2**: Data-in-transit is protected
- **PR.DS-3**: Assets are formally managed throughout removal, transfers, and disposition

### MITRE ATT&CK
- **T1070**: Indicator Removal on Host
- **T1078**: Valid Accounts
- **T1083**: File and Directory Discovery
- **T1087**: Account Discovery

## Best Practices

### 1. Comprehensive Audit Logging
- Enable audit logging for all API server requests
- Configure appropriate audit levels (Metadata, Request, RequestResponse)
- Forward audit logs to centralized logging system
- Implement log retention policies

### 2. Runtime Security Monitoring
- Deploy Falco with eBPF driver for runtime security
- Configure custom rules for organization-specific threats
- Integrate with SIEM for centralized analysis
- Monitor container runtime events

### 3. SIEM Integration
- Forward all security-relevant logs to SIEM
- Configure real-time alerting for critical events
- Implement log correlation and analysis
- Maintain log integrity and availability

### 4. Log Retention and Compliance
- Define retention policies based on compliance requirements
- Implement log rotation to prevent disk space issues
- Encrypt sensitive log data
- Regular backup and archival of logs

## Troubleshooting

### Common Issues

1. **Audit Logging Not Detected**
   - Check if audit policy ConfigMap exists
   - Verify API server configuration
   - Ensure audit webhook is configured

2. **eBPF Tools Not Found**
   - Check for Falco/Tetragon deployments
   - Verify eBPF driver availability
   - Check namespace and label selectors

3. **SIEM Integration Missing**
   - Look for log forwarding DaemonSets
   - Check cloud provider integration
   - Verify SIEM endpoint connectivity

4. **High Risk Scores**
   - Review critical findings first
   - Implement audit logging immediately
   - Deploy security monitoring tools
   - Configure SIEM integration

## Integration with Other Modules

- **K01 (Insecure Workload Configurations)**: Audit logs help detect workload misconfigurations
- **K03 (RBAC Configurations)**: Audit logs are essential for RBAC monitoring
- **K04 (Policy Enforcement)**: Audit logs track policy violations
- **K06 (Insecure Secrets Management)**: Audit logs detect secret access patterns

## References

- [Kubernetes Audit Logging](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)
- [Falco Documentation](https://falco.org/docs/)
- [Tetragon Documentation](https://tetragon.io/docs/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
