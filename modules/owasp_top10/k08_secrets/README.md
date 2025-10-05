# K08 - Secrets Management Failures

## Overview

K08 addresses the critical security risk of secrets management failures in Kubernetes environments. This module helps identify raw secrets in environment variables, ConfigMaps misused for secrets, unencrypted etcd, missing KMS encryption, and exposed vaults.

## Features

### 🔍 **Detection Capabilities**
- **Raw Secret Detection**: Identifies secrets in environment variables and ConfigMaps using regex patterns and entropy analysis
- **Encryption Status**: Checks etcd encryption at rest and KMS encryption configuration
- **Vault Exposure**: Detects exposed vault configurations and credentials
- **Image Pull Secrets**: Analyzes image pull secret scope and permissions
- **Secret Usage**: Maps how secrets are being used across the cluster
- **Pattern Recognition**: Uses regex patterns to detect API keys, passwords, tokens, and other secrets

### 📊 **Analysis Features**
- **Secret Security Scoring**: Calculates overall secret management security score (0-100%)
- **Impact Analysis**: Evaluates the impact of each secret based on usage and exposure
- **Risk Assessment**: Assigns risk scores to identified vulnerabilities
- **Compliance Mapping**: Maps findings to security frameworks (CIS, NIST, etc.)
- **Entropy Analysis**: Uses entropy calculation to detect high-entropy secret-like strings

### 🧪 **Simulation Features**
- **Secret Exfiltration Simulation**: Simulates how secrets could be exfiltrated
- **Detection Testing**: Tests secret detection capabilities with known patterns
- **Rotation Simulation**: Simulates secret rotation scenarios
- **Lab Mode**: Safe testing environment for secret analysis
- **Remediation Templates**: Generates remediation templates and configurations

## Usage

### Basic Analysis
```bash
# Run complete secrets management analysis
kubeshadow owasp k08

# Analyze specific namespace
kubeshadow owasp k08 --namespace production

# Filter by severity
kubeshadow owasp k08 --severity critical
```

### Advanced Features
```bash
# Run secret exfiltration simulation
kubeshadow owasp k08 --simulate

# Enable lab mode for safe secret testing
kubeshadow owasp k08 --lab --simulate

# Confirm secret value exposure (lab mode only)
kubeshadow owasp k08 --lab --confirm --simulate

# Output in JSON format
kubeshadow owasp k08 --output json
```

### Lab Mode
```bash
# Safe secret testing with value exposure
kubeshadow owasp k08 --lab --confirm --simulate

# This enables:
# - Secret value exposure in lab mode
# - Exfiltration simulation
# - Detection testing
# - Rotation simulation
```

## Output Formats

### Table Output (Default)
```
🔐 K08 - Secrets Management Failures Analysis
==============================================

📊 Summary:
  Total Findings: 15
  Critical: 5, High: 6, Medium: 3, Low: 1
  Secret Score: 35.0%
  Raw Secrets Found: 8
  ConfigMap Secrets: 3
  Exposed Secrets: 2
  Etcd Encryption: false
  KMS Encryption: false

🔒 Encryption Status:
  Etcd Encryption: false
  KMS Encryption: false

🔍 Raw Secrets Found: 8
  production/database-password (Opaque) - pass***word
  default/api-key (Opaque) - sk-***def
  backend/jwt-secret (Opaque) - eyJ***J9

⚠️ Secrets in ConfigMaps: 3
  production/app-config.database_url - postgresql://***:5432/db
  default/api-config.api_key - sk-***def
  backend/auth-config.jwt_secret - eyJ***J9

🏦 Vault Configurations: 2
  vault-config (ConfigMap) - https://vault.example.com
  vault-token (Secret) - https://vault.example.com

🚨 Findings:
  🔴 Critical: Secret in ConfigMap
    Description: ConfigMap production/app-config contains secret data in key database_url.
    Resource: configmap/app-config
    Risk Score: 9.5
    Remediation: Move secret data from ConfigMap to Secret resource.

💡 Recommendations:
  1. Remove raw secrets from environment variables and ConfigMaps
  2. Enable etcd encryption at rest
  3. Implement KMS encryption for secrets
```

### JSON Output
```json
{
  "findings": [...],
  "summary": {
    "totalFindings": 15,
    "criticalCount": 5,
    "highCount": 6,
    "mediumCount": 3,
    "lowCount": 1,
    "secretScore": 35.0,
    "rawSecretsFound": 8,
    "configMapSecrets": 3,
    "etcdEncryptionEnabled": false,
    "kmsEncryptionEnabled": false
  },
  "recommendations": [...]
}
```

## Detection Methods

### 1. Raw Secret Detection
- **Pattern Matching**: Uses regex patterns to detect API keys, passwords, tokens
- **Entropy Analysis**: Calculates entropy to identify high-entropy secret-like strings
- **Environment Variables**: Scans pod environment variables for secrets
- **ConfigMap Analysis**: Identifies secrets stored in ConfigMaps
- **Secret Resources**: Analyzes Kubernetes Secret resources

### 2. Encryption Status Detection
- **Etcd Encryption**: Checks for etcd encryption at rest configuration
- **KMS Encryption**: Detects KMS encryption for secrets
- **Encryption Providers**: Identifies encryption providers and configurations
- **Key Management**: Analyzes key rotation and management practices

### 3. Vault Configuration Detection
- **Vault URLs**: Extracts vault URLs from configurations
- **Vault Tokens**: Identifies vault tokens and credentials
- **Vault Exposure**: Detects exposed vault configurations
- **Vault Integration**: Analyzes vault integration patterns

### 4. Image Pull Secret Analysis
- **Scope Analysis**: Evaluates image pull secret scope (namespace vs cluster-wide)
- **Permission Analysis**: Analyzes image pull secret permissions
- **Usage Patterns**: Identifies how image pull secrets are used
- **Security Implications**: Assesses security risks of image pull secrets

## Simulation Events

### Secret Exfiltration Simulation
```json
{
  "secretName": "database-password",
  "namespace": "production",
  "method": "environment-variable",
  "destination": "external-server.com:8080",
  "riskLevel": "high",
  "description": "Simulated exfiltration of database password from environment variable"
}
```

### Secret Detection Test
```json
{
  "testName": "Secret Detection Test",
  "description": "Test secret pattern detected: pass***word",
  "severity": "medium",
  "riskScore": 5.0,
  "metadata": {
    "test_value": "pass***word",
    "test_type": "pattern_detection"
  }
}
```

### Secret Rotation Simulation
```json
{
  "secretName": "database-password-2023",
  "type": "secret-rotation",
  "severity": "medium",
  "description": "Secret database-password-2023 needs rotation due to age or expiration.",
  "riskScore": 6.0
}
```

## Remediation Recommendations

### 1. Move Secrets from ConfigMaps
```yaml
# Before: Secret in ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: "postgresql://user:password@localhost:5432/db"

# After: Proper Secret resource
apiVersion: v1
kind: Secret
metadata:
  name: database-credentials
type: Opaque
data:
  username: <base64-encoded-username>
  password: <base64-encoded-password>
```

### 2. Enable Etcd Encryption
```yaml
# Encryption configuration
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: kms-provider
      endpoint: unix:///tmp/kms.socket
      cachesize: 100
  - identity: {}
```

### 3. Implement KMS Encryption
```yaml
# AWS KMS configuration
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: aws-kms
      endpoint: unix:///tmp/kms.socket
      cachesize: 100
  - identity: {}
```

### 4. Use External Secret Management
```yaml
# Vault integration
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "kubernetes"
```

### 5. Implement Secretless Patterns
```yaml
# Secretless proxy
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secretless-proxy
spec:
  template:
    spec:
      containers:
      - name: secretless
        image: cyberark/secretless-broker:latest
        env:
        - name: SECRETLESS_CREDENTIALS
          value: "database://vault://secret/db#username,database://vault://secret/db#password"
```

## Security Frameworks

### CIS Kubernetes Benchmark
- **Control 5.4.1**: Ensure that the etcd data directory has permissions set to 700 or more restrictive
- **Control 5.4.2**: Ensure that the etcd data directory is owned by etcd
- **Control 5.4.3**: Ensure that the etcd configuration file has permissions set to 644 or more restrictive
- **Control 5.4.4**: Ensure that the etcd configuration file is owned by root

### NIST Cybersecurity Framework
- **PR.DS-1**: Data-at-rest is protected
- **PR.DS-2**: Data-in-transit is protected
- **PR.DS-3**: Assets are formally managed throughout removal, transfers, and disposition
- **PR.DS-4**: Adequate capacity to ensure availability is maintained

### MITRE ATT&CK
- **T1552**: Unsecured Credentials
- **T1555**: Credentials from Password Stores
- **T1556**: Modify Authentication Process
- **T1557**: Adversary-in-the-Middle

## Best Practices

### 1. Secret Management
- Use proper Secret resources instead of ConfigMaps
- Enable etcd encryption at rest
- Implement KMS encryption for secrets
- Use external secret management tools (Vault, AWS Secrets Manager)

### 2. Secret Rotation
- Implement automated secret rotation
- Use short-lived secrets where possible
- Monitor secret age and expiration
- Implement secret rotation policies

### 3. Secret Access
- Use least privilege principle for secret access
- Implement RBAC for secret access
- Monitor and audit secret access
- Use service accounts with minimal permissions

### 4. Secret Detection
- Implement secret scanning in CI/CD pipelines
- Use tools like GitLeaks or TruffleHog
- Regular security assessments
- Monitor for secret exposure

### 5. Secretless Patterns
- Use secretless authentication where possible
- Implement workload identity
- Use external secret management
- Avoid storing secrets in code or configurations

## Troubleshooting

### Common Issues

1. **Secrets in ConfigMaps**
   - Move secrets from ConfigMaps to Secret resources
   - Use ConfigMaps only for non-sensitive data
   - Implement proper secret management

2. **Unencrypted Etcd**
   - Enable etcd encryption at rest
   - Configure encryption providers
   - Implement key rotation

3. **Missing KMS Encryption**
   - Enable KMS encryption for secrets
   - Use cloud provider KMS services
   - Implement envelope encryption

4. **Exposed Vault Configurations**
   - Secure vault configuration and access
   - Use proper authentication
   - Implement access logging

5. **High Risk Scores**
   - Address critical findings first
   - Implement proper secret management
   - Enable encryption at rest
   - Use external secret management

## Integration with Other Modules

- **K01 (Insecure Workload Configurations)**: Secrets complement workload security
- **K03 (RBAC Configurations)**: RBAC controls secret access
- **K05 (Logging and Monitoring)**: Secret access should be logged and monitored
- **K06 (Broken Authentication)**: Secret management affects authentication
- **K07 (Network Segmentation)**: Network policies protect secret access

## References

- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Etcd Encryption](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
