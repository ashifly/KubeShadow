# K09 - Misconfigured Cluster Components

## Overview

K09 addresses the critical security risk of misconfigured cluster components in Kubernetes environments. This module helps identify outdated or misconfigured controllers, webhook misconfigurations, admission webhooks with failurePolicy: Ignore, and CRDs that expose risky code.

## Features

### 🔍 **Detection Capabilities**
- **Webhook Analysis**: Detects MutatingWebhookConfiguration and ValidatingWebhookConfiguration misconfigurations
- **CABundle Detection**: Identifies webhooks missing CABundle configuration
- **Failure Policy Analysis**: Detects webhooks with failurePolicy: Ignore
- **CRD Security**: Analyzes Custom Resource Definitions for security risks
- **Controller Versions**: Identifies outdated controller components
- **Admission Review**: Checks webhook admission review versions

### 📊 **Analysis Features**
- **Component Security Scoring**: Calculates overall component security score (0-100%)
- **Webhook Risk Assessment**: Evaluates webhook security risks and misconfigurations
- **CRD Risk Analysis**: Assesses CRD security implications
- **Controller Assessment**: Evaluates controller security and version status
- **Compliance Mapping**: Maps findings to security frameworks (CIS, NIST, etc.)

### 🧪 **Simulation Features**
- **Webhook Admission Simulation**: Simulates webhook admission tests
- **Pod Admission Testing**: Tests pod admission through webhooks
- **Webhook Connectivity**: Tests webhook connectivity and configuration
- **Mutation Simulation**: Simulates webhook mutation scenarios
- **Lab Mode**: Safe testing environment for component analysis

## Usage

### Basic Analysis
```bash
# Run complete component analysis
kubeshadow owasp k09

# Analyze specific namespace
kubeshadow owasp k09 --namespace production

# Filter by severity
kubeshadow owasp k09 --severity critical
```

### Advanced Features
```bash
# Run webhook admission simulation
kubeshadow owasp k09 --simulate

# Enable lab mode for safe component testing
kubeshadow owasp k09 --lab --simulate

# Output in JSON format
kubeshadow owasp k09 --output json
```

### Lab Mode
```bash
# Safe component testing with simulations
kubeshadow owasp k09 --lab --simulate

# This enables:
# - Webhook admission simulation
# - Pod admission testing
# - Webhook connectivity tests
# - Mutation simulation
```

## Output Formats

### Table Output (Default)
```
🔧 K09 - Misconfigured Cluster Components Analysis
==================================================

📊 Summary:
  Total Findings: 8
  Critical: 2, High: 3, Medium: 2, Low: 1
  Component Score: 65.0%
  Webhooks: 5 (Misconfigured: 3)
  CRDs: 12 (Risky: 2)
  Controllers: 8 (Outdated: 1)

🔗 Webhooks: 5
  🔴 webhook-1 (MutatingWebhook) - high
    ⚠️ Missing CABundle
  🟡 webhook-2 (ValidatingWebhook) - medium
    ⚠️ Failure Policy: Ignore
  🟢 webhook-3 (MutatingWebhook) - low

⚠️ Risky CRDs: 2
  risky-crd-1 (example.com) - high
  risky-crd-2 (example.com) - high

🔄 Outdated Controllers: 1
  controller-1 (controller:1.0) - v1.0

🚨 Findings:
  🔴 Critical: Webhook Missing CABundle
    Description: MutatingWebhook webhook-1 has no CABundle configured.
    Resource: mutatingwebhookconfiguration/webhook-1
    Risk Score: 8.0
    Remediation: Configure CABundle for webhook to ensure secure communication.

💡 Recommendations:
  1. Configure CABundle for all webhooks
  2. Use Fail failure policy instead of Ignore
  3. Implement proper webhook certificate rotation
```

### JSON Output
```json
{
  "findings": [...],
  "summary": {
    "totalFindings": 8,
    "criticalCount": 2,
    "highCount": 3,
    "mediumCount": 2,
    "lowCount": 1,
    "componentScore": 65.0,
    "webhookCount": 5,
    "misconfiguredWebhooks": 3,
    "crdCount": 12,
    "riskyCRDs": 2,
    "outdatedControllers": 1
  },
  "recommendations": [...]
}
```

## Detection Methods

### 1. Webhook Configuration Detection
- **CABundle Analysis**: Checks for missing or empty CABundle configurations
- **Failure Policy**: Detects webhooks with failurePolicy: Ignore
- **Admission Review Versions**: Validates admission review version compatibility
- **Service Configuration**: Analyzes webhook service endpoints and paths
- **Rule Analysis**: Evaluates webhook rules for broad access patterns

### 2. CRD Security Analysis
- **Risky CRD Detection**: Identifies CRDs with potentially dangerous functionality
- **Scope Analysis**: Evaluates CRD scope (Cluster vs Namespace)
- **Validation Schema**: Checks for CRD validation schemas
- **Subresource Analysis**: Analyzes CRD subresources and their security implications
- **Permission Assessment**: Evaluates CRD access permissions

### 3. Controller Assessment
- **Version Detection**: Identifies outdated controller versions
- **Image Analysis**: Analyzes controller container images
- **Security Scanning**: Checks for known vulnerabilities in controller images
- **Update Status**: Evaluates controller update status and recommendations

### 4. Webhook Risk Assessment
- **Broad Access**: Detects webhooks with overly broad API group, resource, or operation access
- **Selector Analysis**: Evaluates namespace and object selector configurations
- **Security Implications**: Assesses webhook security risks and impact

## Simulation Events

### Webhook Admission Test
```json
{
  "testName": "Webhook Admission Test",
  "description": "Test webhook admission for webhook-1",
  "webhookName": "webhook-1",
  "resource": "pods",
  "operation": "CREATE",
  "success": false,
  "error": "Webhook missing CABundle - admission would fail"
}
```

### Pod Admission Simulation
```json
{
  "testName": "Pod Creation",
  "description": "Test pod creation admission",
  "webhookName": "simulated-webhook",
  "resource": "pods",
  "operation": "CREATE",
  "success": true,
  "mutated": false
}
```

### Webhook Risk Analysis
```json
{
  "webhookName": "webhook-1",
  "riskLevel": "high",
  "riskScore": 75.0,
  "issues": ["Missing CABundle", "Ignore failure policy"],
  "recommendations": ["Configure CABundle for secure communication", "Use Fail failure policy for better security"]
}
```

## Remediation Recommendations

### 1. Webhook Security Hardening
```yaml
# Secure MutatingWebhookConfiguration
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: secure-mutating-webhook
webhooks:
- name: secure.mutating.webhook
  clientConfig:
    service:
      name: webhook-service
      namespace: webhook-system
      path: "/mutate"
    caBundle: <base64-encoded-ca-bundle>
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Fail
  admissionReviewVersions: ["v1", "v1beta1"]
  namespaceSelector:
    matchLabels:
      webhook-enabled: "true"
```

### 2. CRD Security Hardening
```yaml
# Secure CRD with validation
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: secure-crd.example.com
spec:
  group: example.com
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              name:
                type: string
                maxLength: 63
  scope: Namespaced
  names:
    plural: secure-crds
    singular: secure-crd
    kind: SecureCRD
```

### 3. Controller Security Hardening
```yaml
# Secure controller deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-controller
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-controller
  template:
    metadata:
      labels:
        app: secure-controller
    spec:
      containers:
      - name: controller
        image: controller:latest
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          limits:
            memory: "128Mi"
            cpu: "100m"
          requests:
            memory: "64Mi"
            cpu: "50m"
```

### 4. Webhook Certificate Management
```yaml
# Webhook certificate secret
apiVersion: v1
kind: Secret
metadata:
  name: webhook-certs
  namespace: webhook-system
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
  ca.crt: <base64-encoded-ca>
```

## Security Frameworks

### CIS Kubernetes Benchmark
- **Control 5.1.1**: Ensure that the cluster-admin role is not used
- **Control 5.1.2**: Ensure that the cluster-admin role is not used
- **Control 5.1.3**: Ensure that the cluster-admin role is not used
- **Control 5.1.4**: Ensure that the cluster-admin role is not used

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

### 1. Webhook Security
- Configure CABundle for all webhooks
- Use Fail failure policy instead of Ignore
- Implement proper webhook certificate rotation
- Use namespaceSelector to restrict webhook scope
- Use objectSelector to restrict webhook scope

### 2. CRD Security
- Implement validation schemas for all CRDs
- Use least privilege principle for CRD access
- Implement RBAC for CRD operations
- Restrict CRD scope where possible
- Monitor CRD usage and access patterns

### 3. Controller Security
- Keep controllers updated to latest versions
- Implement automated controller updates
- Monitor controller versions regularly
- Use least privilege principle for controller access
- Implement controller security scanning

### 4. Component Monitoring
- Implement component monitoring and alerting
- Regular security reviews of component configurations
- Use component admission controllers
- Implement component backup and recovery
- Monitor component performance and errors

### 5. Security Hardening
- Implement comprehensive component security assessment
- Regular security reviews of cluster components
- Use component RBAC policies
- Implement component admission controllers
- Monitor component security events

## Troubleshooting

### Common Issues

1. **Missing CABundle**
   - Configure CABundle for webhook communication
   - Implement certificate rotation
   - Use proper certificate management

2. **Ignore Failure Policy**
   - Change failure policy from Ignore to Fail
   - Implement proper error handling
   - Monitor webhook failures

3. **Risky CRDs**
   - Review CRD permissions and access controls
   - Implement RBAC for CRD access
   - Use validation schemas for CRDs

4. **Outdated Controllers**
   - Update controllers to latest versions
   - Implement automated updates
   - Monitor controller versions

5. **High Risk Scores**
   - Address critical findings first
   - Implement proper component security
   - Enable component monitoring

## Integration with Other Modules

- **K01 (Insecure Workload Configurations)**: Component security complements workload security
- **K03 (RBAC Configurations)**: RBAC controls component access
- **K05 (Logging and Monitoring)**: Component events should be logged and monitored
- **K06 (Broken Authentication)**: Component security affects authentication
- **K07 (Network Segmentation)**: Network policies protect component access
- **K08 (Secrets Management)**: Component security affects secret access

## References

- [Kubernetes Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
