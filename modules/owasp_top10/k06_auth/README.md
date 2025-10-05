# K06 - Broken Authentication Mechanisms

## Overview

K06 addresses the critical security risk of broken authentication mechanisms in Kubernetes environments. This module helps identify weak API server authentication, anonymous access, kubeconfig/token exposure, and public dashboards.

## Features

### 🔍 **Detection Capabilities**
- **API Server Authentication**: Detects weak authentication methods and anonymous access
- **RBAC Configuration**: Checks if Role-Based Access Control is properly enabled
- **Kubeconfig Exposure**: Identifies exposed kubeconfig files in ConfigMaps and Secrets
- **Token Security**: Analyzes service account token age, permissions, and exposure
- **Public Endpoints**: Detects publicly accessible services without authentication
- **Admission Controllers**: Checks for missing security-related admission controllers

### 📊 **Analysis Features**
- **Authentication Scoring**: Calculates overall authentication security score
- **Risk Assessment**: Assigns risk scores to identified vulnerabilities
- **Token Analysis**: Evaluates token age, rotation, and permission levels
- **Credential Exposure**: Identifies exposed credentials and their risk levels
- **Compliance Mapping**: Maps findings to security frameworks (CIS, NIST, etc.)

### 🧪 **Simulation Features**
- **Safe Authentication Tests**: Runs read-only tests to validate authentication
- **Credential Theft Simulation**: Simulates what attackers could do with stolen credentials
- **Public Access Testing**: Tests for publicly accessible endpoints
- **RBAC Effectiveness**: Validates RBAC configuration and effectiveness
- **Lab Mode**: Safe testing environment for credential discovery

## Usage

### Basic Analysis
```bash
# Run complete authentication analysis
kubeshadow owasp k06

# Analyze specific namespace
kubeshadow owasp k06 --namespace production

# Filter by severity
kubeshadow owasp k06 --severity critical
```

### Advanced Features
```bash
# Run authentication tests and simulations
kubeshadow owasp k06 --simulate

# Enable lab mode for safe credential testing
kubeshadow owasp k06 --lab --simulate

# Output in JSON format
kubeshadow owasp k06 --output json
```

### Lab Mode
```bash
# Safe testing with credential discovery
kubeshadow owasp k06 --lab --simulate

# This enables:
# - Safe kubeconfig scanning
# - Credential theft simulation
# - Public endpoint testing
# - Token security analysis
```

## Output Formats

### Table Output (Default)
```
🔐 K06 - Broken Authentication Mechanisms Analysis
==================================================

📊 Summary:
  Total Findings: 8
  Critical: 3, High: 3, Medium: 2, Low: 0
  Auth Score: 35.0%
  Anonymous Access: true
  Exposed Credentials: 5
  Public Endpoints: 2
  Token Age (days): 45
  Credential Rotation: false

🔧 API Server Configuration:
  Anonymous Auth: true
  RBAC Enabled: false
  Audit Logging: true
  Admission Plugins: 2

🚨 Findings:
  🔴 Critical: Anonymous Access Enabled
    Description: Anonymous access to Kubernetes API server is enabled.
    Resource: cluster/all
    Risk Score: 9.5
    Remediation: Disable anonymous access by setting --anonymous-auth=false on API server.

💡 Recommendations:
  1. Disable anonymous access to Kubernetes API server
  2. Enable RBAC with least privilege principle
  3. Implement OIDC or certificate-based authentication
```

### JSON Output
```json
{
  "findings": [...],
  "summary": {
    "totalFindings": 8,
    "criticalCount": 3,
    "highCount": 3,
    "mediumCount": 2,
    "lowCount": 0,
    "authScore": 35.0,
    "anonymousAccess": true,
    "exposedCredentials": 5,
    "publicEndpoints": 2
  },
  "recommendations": [...]
}
```

## Detection Methods

### 1. API Server Authentication Detection
- **Anonymous Access**: Tests for anonymous API server access
- **Authentication Methods**: Checks for weak authentication methods
- **RBAC Status**: Validates Role-Based Access Control configuration
- **Admission Controllers**: Identifies missing security controllers
- **Audit Logging**: Checks for comprehensive audit logging

### 2. Kubeconfig Security Detection
- **File Exposure**: Scans for exposed kubeconfig files
- **ConfigMap Storage**: Detects kubeconfigs stored in ConfigMaps
- **Secret Storage**: Identifies kubeconfigs in Secrets
- **Permission Analysis**: Evaluates file permissions and access controls
- **Location Security**: Checks for kubeconfigs in sensitive directories

### 3. Token Security Analysis
- **Token Age**: Analyzes service account token age
- **Permission Levels**: Evaluates token permissions and privileges
- **Exposure Risk**: Identifies exposed or accessible tokens
- **Rotation Status**: Checks for token rotation policies
- **Service Account Security**: Analyzes service account configurations

### 4. Public Endpoint Detection
- **LoadBalancer Services**: Identifies publicly accessible LoadBalancer services
- **NodePort Services**: Detects NodePort services with public exposure
- **Dashboard Access**: Checks for publicly accessible dashboards
- **Authentication Requirements**: Tests endpoint authentication
- **Network Security**: Evaluates network-level access controls

## Simulation Events

### Anonymous Access Test
```json
{
  "testName": "Anonymous Access Test",
  "description": "Tests if anonymous access is enabled on the API server",
  "success": false,
  "riskLevel": "critical",
  "details": "Anonymous access is enabled - this is a critical security risk"
}
```

### Credential Theft Simulation
```json
{
  "testName": "Token Theft Simulation",
  "description": "Simulates what an attacker could do with a stolen service account token",
  "success": false,
  "riskLevel": "high",
  "details": "Simulation shows 15 service accounts are discoverable"
}
```

### Public Endpoint Test
```json
{
  "testName": "Public Endpoint Test",
  "description": "Tests for publicly accessible endpoints without authentication",
  "success": false,
  "riskLevel": "high",
  "details": "Found 3 public services that may be exposed without authentication"
}
```

## Remediation Recommendations

### 1. Disable Anonymous Access
```yaml
# API Server Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-apiserver-config
data:
  config.yaml: |
    apiServer:
      anonymousAuth: false
      authorization:
        mode: RBAC
```

### 2. Enable RBAC
```yaml
# RBAC Configuration
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: restricted-user
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

### 3. Secure Kubeconfig Files
```bash
# Set proper permissions
chmod 600 ~/.kube/config
chown $USER:$USER ~/.kube/config

# Remove from ConfigMaps
kubectl delete configmap kubeconfig -n default
```

### 4. Implement Token Rotation
```yaml
# Service Account with Token Rotation
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secure-sa
  annotations:
    kubernetes.io/enforce-mountable-secrets: "true"
```

### 5. Secure Public Endpoints
```yaml
# Network Policy for Public Services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-public-access
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: allowed-namespace
```

## Security Frameworks

### CIS Kubernetes Benchmark
- **Control 5.1.1**: Ensure that the cluster-admin role is only used where required
- **Control 5.1.2**: Minimize access to secrets
- **Control 5.1.3**: Minimize wildcard use in Roles and ClusterRoles
- **Control 5.2.1**: Ensure that the --anonymous-auth argument is set to false

### NIST Cybersecurity Framework
- **PR.AC-1**: Identities and credentials are issued, managed, verified, revoked, and audited
- **PR.AC-3**: Remote access is managed
- **PR.AC-4**: Access permissions are managed
- **PR.AC-5**: Network integrity is protected

### MITRE ATT&CK
- **T1078**: Valid Accounts
- **T1083**: File and Directory Discovery
- **T1087**: Account Discovery
- **T1098**: Account Manipulation

## Best Practices

### 1. Strong Authentication
- Disable anonymous access to API server
- Implement OIDC or certificate-based authentication
- Use multi-factor authentication where possible
- Regularly rotate authentication credentials

### 2. RBAC Implementation
- Enable RBAC with least privilege principle
- Create specific roles for different use cases
- Regularly review and audit permissions
- Use ClusterRoles sparingly

### 3. Credential Security
- Secure kubeconfig files with proper permissions
- Remove kubeconfigs from ConfigMaps and Secrets
- Implement token rotation policies
- Monitor for credential exposure

### 4. Public Endpoint Security
- Review all LoadBalancer and NodePort services
- Implement authentication for public services
- Use network policies to restrict access
- Monitor for unauthorized public exposure

### 5. Monitoring and Auditing
- Enable comprehensive audit logging
- Monitor authentication events
- Set up alerts for suspicious activity
- Regularly review access logs

## Troubleshooting

### Common Issues

1. **Anonymous Access Detected**
   - Check API server configuration
   - Verify --anonymous-auth=false is set
   - Review admission controller configuration

2. **RBAC Not Enabled**
   - Enable RBAC in API server configuration
   - Verify --authorization-mode=RBAC is set
   - Check for conflicting authorization modes

3. **Exposed Credentials**
   - Remove kubeconfigs from ConfigMaps/Secrets
   - Secure kubeconfig file permissions
   - Implement credential rotation

4. **Public Endpoints**
   - Review LoadBalancer and NodePort services
   - Implement authentication for public services
   - Use network policies to restrict access

5. **High Risk Scores**
   - Address critical findings first
   - Implement strong authentication
   - Enable comprehensive RBAC
   - Secure all credentials

## Integration with Other Modules

- **K01 (Insecure Workload Configurations)**: Authentication issues can lead to workload compromise
- **K03 (RBAC Configurations)**: Broken authentication affects RBAC effectiveness
- **K05 (Logging and Monitoring)**: Authentication events should be logged and monitored
- **K07 (Security Misconfiguration)**: Authentication is a fundamental security configuration

## References

- [Kubernetes Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
