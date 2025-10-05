# K10 - Outdated and Vulnerable Kubernetes Components

## Overview

K10 addresses the critical security risk of outdated and vulnerable Kubernetes components in production environments. This module helps identify outdated versions of kubelet, API server, ingress, CNI, CSI drivers, container runtime, and known CVEs affecting current versions.

## Features

### 🔍 **Detection Capabilities**
- **Kubernetes Version Analysis**: Detects outdated Kubernetes cluster versions
- **Component Version Detection**: Identifies outdated control plane and worker node components
- **CVE Detection**: Scans for known CVEs affecting current component versions
- **Container Runtime Analysis**: Detects outdated container runtimes (containerd, docker, etc.)
- **CNI/CSI Driver Analysis**: Identifies outdated CNI and CSI driver versions
- **Addon Vulnerability Detection**: Scans for vulnerable addons and extensions

### 📊 **Analysis Features**
- **Vulnerability Scoring**: Calculates overall vulnerability security score (0-100%)
- **CVE Risk Assessment**: Evaluates CVE severity and impact
- **Component Risk Analysis**: Assesses component security risks
- **Upgrade Planning**: Generates upgrade plans and preflight tests
- **Compliance Mapping**: Maps findings to security frameworks (CIS, NIST, etc.)

### 🧪 **Simulation Features**
- **Upgrade Plan Simulation**: Simulates upgrade plans for vulnerable components
- **Preflight Testing**: Tests pre-upgrade requirements and dependencies
- **Vulnerability Scanning**: Simulates vulnerability scanning results
- **Patch Management**: Simulates patch management scenarios
- **Lab Mode**: Safe testing environment for vulnerability analysis

## Usage

### Basic Analysis
```bash
# Run complete vulnerability analysis
kubeshadow owasp k10

# Analyze specific namespace
kubeshadow owasp k10 --namespace production

# Filter by severity
kubeshadow owasp k10 --severity critical
```

### Advanced Features
```bash
# Run vulnerability scanning simulation
kubeshadow owasp k10 --simulate

# Enable lab mode for safe vulnerability testing
kubeshadow owasp k10 --lab --simulate

# Output in JSON format
kubeshadow owasp k10 --output json
```

### Lab Mode
```bash
# Safe vulnerability testing with simulations
kubeshadow owasp k10 --lab --simulate

# This enables:
# - Upgrade plan simulation
# - Preflight testing
# - Vulnerability scanning simulation
# - Patch management simulation
```

## Output Formats

### Table Output (Default)
```
🔍 K10 - Outdated and Vulnerable Kubernetes Components Analysis
===============================================================

📊 Summary:
  Total Findings: 12
  Critical: 3, High: 4, Medium: 3, Low: 2
  Vulnerability Score: 45.0%
  CVEs: 8 (Critical: 2, High: 3)
  Outdated Components: 5
  Kubernetes Version: v1.25.0

🔧 Kubernetes Version: v1.25.0
  Major: 1, Minor: 25
  Build Date: 2023-08-15T10:00:00Z

🔧 Components: 4
  🔴 kube-apiserver (v1.25.0) - high
    ⚠️ Outdated (Latest: v1.28.0)
    🔴 Vulnerable (2 CVEs)
  🔴 kube-controller-manager (v1.25.0) - high
    ⚠️ Outdated (Latest: v1.28.0)
    🔴 Vulnerable (1 CVEs)
  🟡 kube-scheduler (v1.25.0) - medium
    ⚠️ Outdated (Latest: v1.28.0)
  🟢 kube-proxy (v1.25.0) - low
    ⚠️ Outdated (Latest: v1.28.0)

🖥️ Vulnerable Nodes: 2
  node-1 (v1.25.0) - containerd://1.6.0
    CVEs: 2
  node-2 (v1.25.0) - containerd://1.6.0
    CVEs: 1

🔌 Outdated Addons: 3
  nginx-ingress (ingress) - v1.2.0 (Latest: v1.8.0)
  calico (cni) - v3.20.0 (Latest: v3.26.0)
  aws-ebs-csi-driver (csi) - v1.15.0 (Latest: v1.20.0)

🚨 Findings:
  🔴 Critical: Outdated Kubernetes Version
    Description: Kubernetes version v1.25.0 is outdated and may contain security vulnerabilities.
    Resource: cluster/all
    Risk Score: 8.0
    Remediation: Upgrade Kubernetes to the latest stable version.

📋 Upgrade Plans: 4
  kubernetes: v1.25.0 → v1.28.0 (high)
    Steps: 5
    Pre-checks: 4
  kubelet: v1.25.0 → v1.28.0 (medium)
    Steps: 5
    Pre-checks: 4
  containerd: v1.6.0 → v1.7.0 (low)
    Steps: 5
    Pre-checks: 4
  calico: v3.20.0 → v3.26.0 (medium)
    Steps: 5
    Pre-checks: 4

🧪 Preflight Tests: 6
  Required: 4
  Optional: 2

💡 Recommendations:
  1. Upgrade Kubernetes to the latest stable version
  2. Implement automated Kubernetes updates
  3. Monitor Kubernetes security advisories
  4. Upgrade all outdated components to latest versions
  5. Implement automated node updates
```

### JSON Output
```json
{
  "findings": [...],
  "summary": {
    "totalFindings": 12,
    "criticalCount": 3,
    "highCount": 4,
    "mediumCount": 3,
    "lowCount": 2,
    "vulnerabilityScore": 45.0,
    "cveCount": 8,
    "criticalCVEs": 2,
    "highCVEs": 3,
    "outdatedComponents": 5,
    "kubernetesVersion": "v1.25.0"
  },
  "recommendations": [...]
}
```

## Detection Methods

### 1. Kubernetes Version Detection
- **Server Version**: Queries Kubernetes API server version
- **Component Versions**: Detects control plane component versions
- **Node Versions**: Identifies worker node kubelet versions
- **Build Information**: Analyzes build dates and commit hashes
- **Version Comparison**: Compares against known stable versions

### 2. CVE Detection
- **CVE Database Integration**: Cross-references with NVD and vendor feeds
- **Version Mapping**: Maps component versions to known CVEs
- **Severity Assessment**: Evaluates CVE severity and impact
- **Fix Availability**: Checks for available patches and updates
- **Exploitability**: Assesses exploitability and attack vectors

### 3. Component Analysis
- **Control Plane**: Analyzes API server, controller manager, scheduler
- **Worker Nodes**: Evaluates kubelet, kube-proxy, container runtime
- **Addons**: Scans ingress controllers, CNI plugins, CSI drivers
- **Extensions**: Detects custom controllers and operators
- **Dependencies**: Identifies vulnerable dependencies

### 4. Container Runtime Analysis
- **Runtime Detection**: Identifies containerd, docker, CRI-O versions
- **Vulnerability Scanning**: Scans for runtime-specific CVEs
- **Configuration Analysis**: Evaluates runtime security configurations
- **Update Status**: Checks for available runtime updates

## Simulation Events

### Upgrade Plan Simulation
```json
{
  "component": "kubernetes",
  "currentVersion": "v1.25.0",
  "targetVersion": "v1.28.0",
  "riskLevel": "high",
  "steps": [
    {
      "step": 1,
      "description": "Backup current kubernetes configuration",
      "command": "kubectl get kubernetes -o yaml > kubernetes-backup.yaml",
      "riskLevel": "low"
    }
  ],
  "preChecks": [
    {
      "name": "Cluster Health Check",
      "description": "Verify cluster is healthy before upgrade",
      "command": "kubectl get nodes",
      "required": true
    }
  ]
}
```

### CVE Detection Simulation
```json
{
  "id": "CVE-2023-1234",
  "description": "Kubelet vulnerability in version 1.25.x",
  "severity": "high",
  "score": 8.5,
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "affectedVersions": ["v1.25.0", "v1.25.1", "v1.25.2"],
  "fixedVersions": ["v1.25.3", "v1.26.0"]
}
```

### Preflight Test Simulation
```json
{
  "name": "Cluster Health",
  "description": "Verify cluster is healthy and all nodes are ready",
  "command": "kubectl get nodes --no-headers | grep -v Ready",
  "required": true,
  "metadata": {
    "test_type": "preflight",
    "component": "upgrade"
  }
}
```

## Remediation Recommendations

### 1. Kubernetes Upgrade
```bash
# Backup cluster configuration
kubectl get all --all-namespaces -o yaml > backup.yaml

# Upgrade control plane
kubeadm upgrade plan
kubeadm upgrade apply v1.28.0

# Upgrade worker nodes
kubeadm upgrade node

# Verify upgrade
kubectl version
kubectl get nodes
```

### 2. Component Updates
```bash
# Update kubelet
kubeadm upgrade node

# Update container runtime
systemctl stop containerd
apt-get update && apt-get install containerd.io
systemctl start containerd

# Update CNI plugin
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.0/manifests/calico.yaml
```

### 3. CVE Mitigation
```bash
# Apply security patches
kubectl patch deployment kube-apiserver -p '{"spec":{"template":{"spec":{"containers":[{"name":"kube-apiserver","image":"k8s.gcr.io/kube-apiserver:v1.28.0"}]}}}}'

# Restart affected components
kubectl rollout restart deployment kube-apiserver
kubectl rollout restart deployment kube-controller-manager
kubectl rollout restart deployment kube-scheduler
```

### 4. Vulnerability Scanning
```bash
# Install Trivy for vulnerability scanning
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan cluster for vulnerabilities
trivy k8s cluster

# Scan specific images
trivy image k8s.gcr.io/kube-apiserver:v1.25.0
```

## Security Frameworks

### CIS Kubernetes Benchmark
- **Control 1.1**: Ensure that the API server pod specification file has permissions of 644 or more restrictive
- **Control 1.2**: Ensure that the API server pod specification file ownership is set to root:root
- **Control 1.3**: Ensure that the controller manager pod specification file has permissions of 644 or more restrictive
- **Control 1.4**: Ensure that the controller manager pod specification file ownership is set to root:root

### NIST Cybersecurity Framework
- **PR.AC-1**: Identities and credentials are issued, managed, verified, revoked, and audited
- **PR.AC-2**: Physical access to assets is managed and protected
- **PR.AC-3**: Remote access is managed
- **PR.AC-4**: Access permissions and authorizations are managed

### MITRE ATT&CK
- **T1078**: Valid Accounts
- **T1078.004**: Cloud Accounts
- **T1078.005**: Default Accounts
- **T1078.006**: Domain Accounts

## Best Practices

### 1. Vulnerability Management
- Implement automated vulnerability scanning
- Use CVE monitoring and alerting systems
- Implement patch management procedures
- Regular security assessments and penetration testing
- Use vulnerability management tools (Trivy, Snyk, etc.)

### 2. Component Updates
- Keep all components updated to latest versions
- Implement automated update procedures
- Test updates in non-production environments
- Use rolling updates for zero-downtime upgrades
- Monitor component health after updates

### 3. CVE Response
- Address critical CVEs immediately
- Implement emergency patching procedures
- Monitor CVE databases regularly
- Use container image scanning
- Implement security scanning in CI/CD pipelines

### 4. Upgrade Planning
- Create comprehensive upgrade plans
- Test upgrades in lab environments
- Implement preflight checks
- Use backup and recovery procedures
- Monitor cluster health during upgrades

### 5. Security Monitoring
- Implement security monitoring and alerting
- Use vulnerability scanning tools
- Monitor security advisories and bulletins
- Regular security training and awareness
- Implement incident response procedures

## Troubleshooting

### Common Issues

1. **Outdated Kubernetes Version**
   - Upgrade to latest stable version
   - Implement automated updates
   - Monitor security advisories

2. **Critical CVEs**
   - Apply emergency patches immediately
   - Implement additional security controls
   - Conduct security assessment

3. **Component Vulnerabilities**
   - Update all vulnerable components
   - Implement automated scanning
   - Use vulnerability management tools

4. **Upgrade Failures**
   - Check preflight requirements
   - Verify backup and recovery procedures
   - Test upgrades in lab environments

5. **High Vulnerability Scores**
   - Address critical findings first
   - Implement comprehensive vulnerability management
   - Enable automated scanning and monitoring

## Integration with Other Modules

- **K01 (Insecure Workload Configurations)**: Component security complements workload security
- **K03 (RBAC Configurations)**: RBAC controls component access
- **K05 (Logging and Monitoring)**: Component events should be logged and monitored
- **K06 (Broken Authentication)**: Component security affects authentication
- **K07 (Network Segmentation)**: Network policies protect component access
- **K08 (Secrets Management)**: Component security affects secret access
- **K09 (Misconfigured Components)**: Component misconfigurations affect vulnerability exposure

## References

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Trivy Vulnerability Scanner](https://trivy.dev/)
- [Snyk Container Security](https://snyk.io/)
