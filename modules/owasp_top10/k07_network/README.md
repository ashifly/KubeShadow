# K07 - Missing Network Segmentation Controls

## Overview

K07 addresses the critical security risk of missing network segmentation controls in Kubernetes environments. This module helps identify lack of NetworkPolicies, hostNetwork usage, overly broad service exposure, and CNI misconfigurations.

## Features

### 🔍 **Detection Capabilities**
- **NetworkPolicy Analysis**: Detects missing or misconfigured NetworkPolicies
- **Host Network Detection**: Identifies pods using host network, hostPID, and hostIPC
- **Public Service Exposure**: Detects NodePort and LoadBalancer services open to public CIDRs
- **CNI Configuration**: Analyzes CNI provider capabilities and NetworkPolicy support
- **Network Connectivity**: Tests pod-to-pod connectivity and network segmentation
- **Blast Radius Analysis**: Calculates potential impact if a pod is compromised

### 📊 **Analysis Features**
- **Network Security Scoring**: Calculates overall network security score (0-100%)
- **Blast Radius Calculation**: Measures potential lateral movement in case of compromise
- **Network Matrix**: Visual representation of allowed network flows
- **Risk Assessment**: Assigns risk scores to identified vulnerabilities
- **Compliance Mapping**: Maps findings to security frameworks (CIS, NIST, etc.)

### 🧪 **Simulation Features**
- **Safe Connectivity Tests**: Runs controlled network connectivity tests
- **Network Probes**: Tests pod-to-pod and service connectivity
- **Cross-Namespace Testing**: Validates network segmentation between namespaces
- **Lab Mode**: Safe testing environment for network analysis
- **Network Policy Templates**: Generates remediation templates

## Usage

### Basic Analysis
```bash
# Run complete network segmentation analysis
kubeshadow owasp k07

# Analyze specific namespace
kubeshadow owasp k07 --namespace production

# Filter by severity
kubeshadow owasp k07 --severity critical
```

### Advanced Features
```bash
# Run network connectivity tests
kubeshadow owasp k07 --simulate

# Enable lab mode for safe network testing
kubeshadow owasp k07 --lab --simulate

# Output in JSON format
kubeshadow owasp k07 --output json
```

### Lab Mode
```bash
# Safe network testing with connectivity probes
kubeshadow owasp k07 --lab --simulate

# This enables:
# - Controlled network connectivity tests
# - Pod-to-pod connectivity analysis
# - Cross-namespace network testing
# - Network probe generation
```

## Output Formats

### Table Output (Default)
```
🌐 K07 - Missing Network Segmentation Controls Analysis
======================================================

📊 Summary:
  Total Findings: 12
  Critical: 3, High: 4, Medium: 3, Low: 2
  Network Score: 45.0%
  Network Policies: 2
  Host Network Pods: 5
  Public Services: 3
  CNI Provider: Calico
  Default Deny Enabled: false
  Blast Radius: 15

🔧 CNI Configuration:
  Provider: Calico
  Features: NetworkPolicies, IPAM

🛡️ Network Policies:
  default/web-policy (3 rules)
  production/api-policy (2 rules)

⚠️ Host Network Pods: 5
  default/nginx-ingress
  kube-system/kube-proxy
  monitoring/prometheus

🌍 Public Services: 3
  default/web-service (LoadBalancer)
  production/api-service (NodePort)
  monitoring/grafana-service (LoadBalancer)

🚨 Findings:
  🔴 Critical: No NetworkPolicies Found
    Description: No NetworkPolicies are configured in the cluster, leaving all network traffic unrestricted.
    Resource: cluster/all
    Risk Score: 9.5
    Remediation: Implement NetworkPolicies to control network traffic and prevent lateral movement.

💡 Recommendations:
  1. Implement default deny NetworkPolicies
  2. Use micro-segmentation to limit lateral movement
  3. Avoid host network for pods unless absolutely necessary
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
    "networkScore": 45.0,
    "networkPoliciesCount": 2,
    "hostNetworkPods": 5,
    "publicServices": 3,
    "cniProvider": "Calico"
  },
  "recommendations": [...]
}
```

## Detection Methods

### 1. NetworkPolicy Detection
- **Policy Coverage**: Analyzes NetworkPolicy coverage across namespaces
- **Rule Analysis**: Evaluates ingress and egress rules
- **Default Deny**: Checks for default deny policies
- **Pod Selectors**: Analyzes pod selector configurations
- **Namespace Isolation**: Validates namespace-level network isolation

### 2. Host Network Detection
- **Host Network Usage**: Identifies pods using host network
- **Host PID Usage**: Detects pods using host PID namespace
- **Host IPC Usage**: Finds pods using host IPC namespace
- **Security Implications**: Assesses security risks of host namespace sharing
- **Bypass Detection**: Identifies network segmentation bypasses

### 3. Public Service Detection
- **LoadBalancer Services**: Identifies publicly accessible LoadBalancer services
- **NodePort Services**: Detects NodePort services with public exposure
- **External IPs**: Checks for services with external IP addresses
- **Public CIDRs**: Validates exposure to public IP ranges
- **Access Controls**: Tests service authentication requirements

### 4. CNI Configuration Analysis
- **Provider Detection**: Identifies CNI provider (Calico, Flannel, Weave, Cilium)
- **Feature Support**: Checks for NetworkPolicy support
- **Configuration Analysis**: Reviews CNI configuration
- **Capability Assessment**: Evaluates CNI security features
- **Migration Recommendations**: Suggests CNI upgrades if needed

## Simulation Events

### Pod-to-Pod Connectivity Test
```json
{
  "testName": "Pod-to-Pod Connectivity Test",
  "description": "Tests connectivity between pods in the same namespace",
  "source": "default/web-pod",
  "target": "default/api-pod",
  "protocol": "TCP",
  "port": 80,
  "success": true,
  "latency": "5ms"
}
```

### Cross-Namespace Connectivity Test
```json
{
  "testName": "Cross-Namespace Connectivity Test",
  "description": "Tests connectivity between pods in different namespaces",
  "source": "frontend/web-pod",
  "target": "backend/api-pod",
  "protocol": "TCP",
  "port": 8080,
  "success": true,
  "latency": "8ms"
}
```

### Blast Radius Analysis
```json
{
  "podName": "compromised-pod",
  "namespace": "default",
  "reachablePods": 15,
  "reachableServices": 8,
  "riskLevel": "high",
  "connections": [
    {
      "source": "default/compromised-pod",
      "target": "database/mysql",
      "protocol": "TCP",
      "port": 3306,
      "allowed": true,
      "reason": "No NetworkPolicy blocking"
    }
  ]
}
```

## Remediation Recommendations

### 1. Implement Default Deny NetworkPolicies
```yaml
# Default deny all traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### 2. Allow DNS Resolution
```yaml
# Allow DNS queries
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

### 3. Micro-Segmentation
```yaml
# Allow specific pod-to-pod communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 8080
```

### 4. Namespace Isolation
```yaml
# Isolate namespace from others
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-namespace
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: production
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: production
```

## Security Frameworks

### CIS Kubernetes Benchmark
- **Control 5.3.1**: Ensure that the CNI in use supports NetworkPolicies
- **Control 5.3.2**: Ensure that all Namespaces have NetworkPolicies defined
- **Control 5.3.3**: Ensure that the default namespace is not used
- **Control 5.3.4**: Ensure that the default namespace has a NetworkPolicy

### NIST Cybersecurity Framework
- **PR.AC-5**: Network integrity is protected
- **PR.DS-2**: Data-in-transit is protected
- **PR.IP-1**: A baseline configuration of information technology/industrial control systems is created and maintained
- **PR.IP-12**: A vulnerability management plan is developed and implemented

### MITRE ATT&CK
- **T1021**: Remote Services
- **T1071**: Application Layer Protocol
- **T1090**: Proxy
- **T1105**: Ingress Tool Transfer

## Best Practices

### 1. Network Segmentation
- Implement default deny NetworkPolicies
- Use micro-segmentation for fine-grained control
- Isolate namespaces with NetworkPolicies
- Apply least privilege network access

### 2. Host Network Security
- Avoid host network for pods unless necessary
- Use regular pod networking instead
- Monitor host network usage
- Document business justification for host network

### 3. Service Exposure
- Use ClusterIP services with ingress controllers
- Avoid NodePort and LoadBalancer unless necessary
- Implement proper access controls for public services
- Monitor service exposure and access

### 4. CNI Selection
- Choose CNI that supports NetworkPolicies
- Consider Calico, Cilium, or Weave for advanced features
- Evaluate CNI security capabilities
- Plan for CNI migration if needed

### 5. Monitoring and Auditing
- Monitor network traffic and connections
- Set up alerts for network policy violations
- Regular network security assessments
- Document and review network policies

## Troubleshooting

### Common Issues

1. **No NetworkPolicies Found**
   - Check if CNI supports NetworkPolicies
   - Verify NetworkPolicy CRD is installed
   - Review namespace configurations

2. **Host Network Usage**
   - Identify pods using host network
   - Review business justification
   - Migrate to pod networking where possible

3. **Public Service Exposure**
   - Review LoadBalancer and NodePort services
   - Implement access controls
   - Consider using ingress controllers

4. **CNI Configuration Issues**
   - Verify CNI provider installation
   - Check CNI configuration
   - Consider CNI migration if needed

5. **High Blast Radius**
   - Implement network segmentation
   - Use micro-segmentation
   - Apply default deny policies
   - Monitor network traffic

## Integration with Other Modules

- **K01 (Insecure Workload Configurations)**: Network policies complement workload security
- **K03 (RBAC Configurations)**: Network and RBAC work together for defense in depth
- **K05 (Logging and Monitoring)**: Network events should be logged and monitored
- **K06 (Broken Authentication)**: Network segmentation helps contain authentication failures

## References

- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [CNI Network Plugins](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
