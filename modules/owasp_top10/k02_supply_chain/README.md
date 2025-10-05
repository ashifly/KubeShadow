# K02 - Supply Chain Vulnerabilities

## Overview

The K02 module is a comprehensive supply chain security scanner for Kubernetes that detects risky images, mutable registries, weak CI pipelines, GitOps misconfigurations, and image provenance gaps.

## Features

### 🔍 Detector
- **Image enumeration**: Extracts all container images from PodSpecs
- **Image digest analysis**: Fetches and analyzes image digests
- **Vulnerability scanning**: Integrates with Trivy/Grype for CVE detection
- **Registry analysis**: Checks for public/mutable registries
- **Tag pattern detection**: Identifies risky patterns like `:latest`
- **Image pull secrets**: Detects and analyzes imagePullSecrets usage

### 📈 Analyzer
- **CVE ranking**: Prioritizes by vulnerability severity and CVSS scores
- **Provenance verification**: Checks for signed images (cosign)
- **Registry exposure**: Identifies anonymous push capabilities
- **Usage analysis**: Tracks image usage across namespaces
- **Risk scoring**: CVSS-style scoring for supply chain risks

### 🧪 Simulator (Lab Mode)
- **Non-destructive testing**: Safe simulation with `--lab` flag
- **Attack vector demonstration**: Shows how compromises propagate
- **What-if scenarios**: Generates manifests showing potential impact
- **Educational content**: Explains supply chain attack vectors

### 📄 Output Formats
- **JSON report**: Complete findings in `supplychain_report.json`
- **CSV export**: Structured data for analysis
- **Remediation guides**: CI/GitOps hardening recommendations
- **Kubectl commands**: Ready-to-apply security policies

## Usage

### Basic Commands

```bash
# Basic supply chain scan
kubeshadow owasp k02

# Scan with Trivy integration
kubeshadow owasp k02 --trivy-url http://trivy:8080

# Custom output location
kubeshadow owasp k02 --output ./supplychain-report.json

# Lab simulation
kubeshadow owasp k02 --lab --simulate

# Filter by severity
kubeshadow owasp k02 --severity critical,high

# Scan specific namespace
kubeshadow owasp k02 --namespace kube-system
```

### Command Options

| Flag | Description | Default |
|------|-------------|---------|
| `--output, -o` | Output file path for findings | `./supplychain_report.json` |
| `--trivy-url` | Trivy server URL for vulnerability scanning | None |
| `--namespace, -n` | Scan specific namespace | All namespaces |
| `--severity` | Filter by severity levels | All severities |
| `--lab` | Enable lab mode for non-destructive testing | `false` |
| `--simulate` | Run simulation to demonstrate potential impact | `false` |
| `--kubeconfig` | Path to kubeconfig file | `~/.kube/config` |

## Vulnerability Detection

### Critical Vulnerabilities (CVSS 15.0+)
- **Multiple high-severity CVEs**: Multiple critical vulnerabilities
- **Unsigned images in production**: No provenance verification
- **Mutable registries**: Images can be overwritten
- **Public registry exposure**: Images in public registries

### High Vulnerabilities (CVSS 10.0-14.9)
- **High-severity CVEs**: Critical and high CVSS scores
- **Latest tag usage**: Using `:latest` or no tag
- **Cross-namespace usage**: Images used in multiple namespaces
- **No CI scanning**: Missing vulnerability scanning

### Medium Vulnerabilities (CVSS 5.0-9.9)
- **Medium-severity CVEs**: Medium CVSS scores
- **Public registry**: Using public container registries
- **No SBOM**: Missing Software Bill of Materials
- **Infrequent scanning**: Outdated vulnerability scans

### Low Vulnerabilities (CVSS <5.0)
- **Low-severity CVEs**: Low CVSS scores
- **Minor configuration issues**: Non-critical misconfigurations

## Risk Scoring

The module uses a comprehensive scoring system:

```go
// Example risk calculation
riskScore := 0.0

// Latest tag (Medium)
if strings.HasSuffix(imageName, ":latest") {
    riskScore += 5.0
}

// Mutable registry (High)
if isMutableRegistry(registryURL) {
    riskScore += 7.0
}

// Public registry (Medium)
if isPublicRegistry(registryURL) {
    riskScore += 3.0
}

// No signature (Medium)
if !hasSignature {
    riskScore += 4.0
}

// No CI scanning (Low)
if !hasScanning {
    riskScore += 2.0
}

// High usage (Low)
if usageCount > 5 {
    riskScore += 2.0
}

// CVE scores (Variable)
for _, vuln := range vulnerabilities {
    riskScore += vuln.CVSS
}
```

## Output Formats

### JSON Structure

```json
{
  "scanMetadata": {
    "scanId": "kubeshadow-supplychain-1234567890",
    "timestamp": "2025-01-10T21:50:00Z",
    "version": "1.0.0",
    "scanner": "KubeShadow K02",
    "totalImages": 25
  },
  "summary": {
    "totalImages": 25,
    "vulnerableImages": 8,
    "totalVulnerabilities": 45,
    "averageRiskScore": 6.2,
    "maxRiskScore": 15.8,
    "severityBreakdown": {
      "critical": 2,
      "high": 3,
      "medium": 2,
      "low": 1
    },
    "registryBreakdown": {
      "publicRegistries": 15,
      "privateRegistries": 10,
      "mutableRegistries": 20
    }
  },
  "findings": [
    {
      "imageName": "nginx:latest",
      "imageDigest": "sha256:abc123...",
      "namespace": "multiple",
      "severity": "HIGH",
      "riskScore": 12.5,
      "vulnerabilities": [
        {
          "cveId": "CVE-2023-1234",
          "severity": "HIGH",
          "cvss": 7.5,
          "description": "Remote code execution vulnerability",
          "packageName": "openssl",
          "packageVersion": "1.1.1",
          "fixedVersion": "1.1.1t"
        }
      ],
      "registryInfo": {
        "registryUrl": "docker.io",
        "isPublic": true,
        "isMutable": true,
        "requiresAuth": false,
        "anonymousPush": false
      },
      "provenanceInfo": {
        "hasSignature": false,
        "hasAttestation": false,
        "signerIdentity": "",
        "buildTimestamp": "",
        "sourceRepo": "",
        "buildSystem": ""
      },
      "ciInfo": {
        "hasCI": false,
        "ciSystem": "",
        "hasSBOM": false,
        "hasScanning": false,
        "scanFrequency": "",
        "lastScanDate": ""
      },
      "remediation": {
        "description": "Implement comprehensive supply chain security measures",
        "imageHardening": [
          "Use specific image tags instead of :latest",
          "Sign images with cosign",
          "Use distroless or minimal base images",
          "Regularly update base images"
        ],
        "ciHardening": [
          "Implement automated vulnerability scanning",
          "Generate SBOM for all images",
          "Use multi-stage builds",
          "Implement image signing in CI/CD"
        ],
        "gitOpsHardening": [
          "Use image digest instead of tags",
          "Implement image policy enforcement",
          "Use admission controllers for image validation",
          "Implement automated image updates"
        ]
      }
    }
  ]
}
```

## Remediation

### Image Hardening

```bash
# Use specific tags instead of latest
FROM nginx:1.21.6

# Sign images with cosign
cosign sign --key cosign.key myregistry/myimage:v1.0.0

# Use distroless images
FROM gcr.io/distroless/java:11
```

### CI/CD Hardening

```yaml
# GitHub Actions example
- name: Build and scan image
  run: |
    docker build -t $IMAGE_NAME:$TAG .
    trivy image --format json --output scan.json $IMAGE_NAME:$TAG
    cosign sign --key cosign.key $IMAGE_NAME:$TAG

- name: Generate SBOM
  run: |
    syft $IMAGE_NAME:$TAG -o spdx-json=sbom.json
```

### GitOps Hardening

```yaml
# Image policy enforcement
apiVersion: v1
kind: ConfigMap
metadata:
  name: image-policy
  namespace: gatekeeper-system
data:
  policy.rego: |
    package imagepolicy
    
    deny[msg] {
        input.request.object.spec.containers[_].image
        not startswith(input.request.object.spec.containers[_].image, "sha256:")
        msg := "Images must use digest instead of tags"
    }
```

## Integration

### Trivy Integration

```bash
# Start Trivy server
trivy server --listen 0.0.0.0:8080

# Scan with Trivy
kubeshadow owasp k02 --trivy-url http://trivy:8080
```

### CI/CD Integration

```yaml
# GitHub Actions workflow
- name: Supply Chain Security Scan
  run: |
    kubeshadow owasp k02 --output ./supplychain-report.json
    
- name: Upload findings
  uses: actions/upload-artifact@v3
  with:
    name: supplychain-findings
    path: ./supplychain-report.json
```

## Lab Simulation

The lab simulation demonstrates supply chain attack vectors:

```yaml
# Simulation manifest
apiVersion: v1
kind: Pod
metadata:
  name: supply-chain-simulation
spec:
  containers:
  - name: simulation
    image: alpine:latest
    command: ["sh", "-c"]
    args:
    - echo '🔗 KubeShadow Supply Chain Simulator'
    - echo '📊 Demonstrating supply chain attack vectors...'
    - echo '⚠️  This is a simulation - no actual harm done'
    - echo '🔍 Showing how compromised images could propagate'
```

## Security Considerations

- **Non-destructive**: All scans are read-only
- **Lab mode only**: Simulation features are safe
- **Minimal permissions**: Only requires read access to pods
- **Secure defaults**: Follows security best practices

## Troubleshooting

### Common Issues

1. **Trivy connection failed**: Ensure Trivy server is running and accessible
2. **Permission denied**: Ensure proper RBAC permissions for pod access
3. **Registry access**: Some registries may require authentication

### Debug Mode

```bash
# Enable verbose logging
kubeshadow owasp k02 --kubeconfig ~/.kube/config -v
```

## References

- [Supply Chain Security Best Practices](https://slsa.dev/)
- [Cosign Image Signing](https://github.com/sigstore/cosign)
- [Trivy Vulnerability Scanner](https://github.com/aquasecurity/trivy)
- [SBOM Generation](https://github.com/anchore/syft)
- [Kubernetes Image Security](https://kubernetes.io/docs/concepts/containers/images/)
