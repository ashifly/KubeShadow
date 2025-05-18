# Cloud Attack Modules

This document covers two modules for testing cloud-related vulnerabilities:
- `cloud-elevator`: For testing cloud privilege escalation vectors
- `metadata-hijack`: For exploiting cloud metadata services

## Cloud Elevator Module

### Usage
```bash
kubeshadow cloud-elevator [--kubeconfig PATH]
```

### Features
- Detects cloud provider environment (AWS, GCP, Azure)
- Tests for IMDSv2 bypass in AWS
- Checks for metadata service access from pods
- Identifies potential privilege escalation paths

### Examples
```bash
# Basic cloud reconnaissance
kubeshadow cloud-elevator

# With specific kubeconfig
kubeshadow cloud-elevator --kubeconfig ~/.kube/config
```

## Metadata Hijack Module

### Usage
```bash
kubeshadow metadata-hijack [--kubeconfig PATH]
```

### Features
- Tests for cloud metadata service access
- Attempts credential/token extraction
- Identifies vulnerable pod configurations
- Supports AWS, GCP, and Azure environments

### Examples
```bash
# Test metadata service access
kubeshadow metadata-hijack

# With specific kubeconfig
kubeshadow metadata-hijack --kubeconfig ~/.kube/config
```

## Common Attack Vectors

1. **Host Network Access**
   - Pods with `hostNetwork: true`
   - Direct access to metadata service IP

2. **IMDS Credential Access**
   - AWS: Instance profile credentials
   - GCP: Service account tokens
   - Azure: Managed identity tokens

3. **Container Escape**
   - Privileged containers
   - Host path mounts
   - Capability escalation

## Security Recommendations

1. Block metadata service access:
   - Use cloud provider security groups
   - Implement network policies
   - Configure IMDSv2 in AWS

2. Limit pod privileges:
   - Avoid `hostNetwork: true`
   - Restrict privileged containers
   - Use minimal IAM roles

3. Monitor for suspicious access:
   - Enable cloud audit logging
   - Monitor metadata service access
   - Alert on credential exfiltration