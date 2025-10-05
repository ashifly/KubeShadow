# K03 - Overly Permissive RBAC Configurations

## Overview

K03 focuses on identifying overly permissive Role-Based Access Control (RBAC) configurations in Kubernetes clusters that could lead to privilege escalation attacks. This module builds RBAC graphs and performs what-if analysis to find potential escalation chains.

## Features

### 🔍 Detector
- Enumerates all RBAC resources:
  - Roles and ClusterRoles
  - RoleBindings and ClusterRoleBindings  
  - ServiceAccounts
  - Maps which subjects have which verbs on which resources

### 📊 Analyzer
- Computes shortest escalation paths to target privileges
- Path scoring based on minimum number of changes required
- Risk assessment for each RBAC binding
- Identifies dangerous permission combinations

### 🧪 Simulator
- Generates non-destructive lab demonstrations
- Shows how privilege escalation could occur
- Creates commented manifests for educational purposes
- Supports `--apply` flag only in `--lab` mode

### 📄 Outputs
- `rbac_graph.json` - Graph format with nodes and edges
- Prioritized list of risky bindings
- Remediation suggestions with kubectl apply commands
- Falco rules for monitoring

## Usage

### Basic Scan
```bash
kubeshadow owasp k03
```

### Namespace-Specific Scan
```bash
kubeshadow owasp k03 --namespace kube-system
```

### Lab Simulation
```bash
kubeshadow owasp k03 --lab --simulate
```

### Apply Lab Environment
```bash
kubeshadow owasp k03 --lab --apply
```

### Filter by Severity
```bash
kubeshadow owasp k03 --severity critical,high
```

## Graph Structure

The RBAC graph uses the following node types:

### Nodes
- **Subject Nodes**: ServiceAccounts, Users, Groups
- **Resource Nodes**: Roles, ClusterRoles, API Resources
- **Permission Nodes**: Specific resource-verb combinations

### Edges
- **Binding Edges**: Subject → Role relationships
- **Permission Edges**: Role → Resource relationships
- **Weighted Edges**: Risk scores for path analysis

## Escalation Path Analysis

The analyzer identifies common escalation patterns:

1. **Role Binding Creation**: Subjects that can create RoleBindings
2. **ClusterRole Binding**: Subjects that can bind to ClusterRoles
3. **Privilege Escalation**: Multi-step paths to admin privileges
4. **Wildcard Permissions**: Overly broad resource access

## Risk Scoring

Risk scores are calculated based on:

- **Permission Scope**: Cluster-wide vs namespace-scoped
- **Verb Danger**: Create/Delete vs Read operations
- **Resource Sensitivity**: Secrets vs ConfigMaps
- **Wildcard Usage**: `*` permissions are high risk

## Remediation

### Least Privilege Principles
- Remove wildcard permissions (`*`)
- Use specific resource names
- Remove unnecessary verbs
- Prefer built-in roles when possible

### Admission Controllers
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-policy
data:
  policy.yaml: |
    rules:
    - level: Error
      users: ["*"]
      verbs: ["create", "update", "patch"]
      resources: ["clusterrolebindings"]
      message: "ClusterRoleBinding creation is restricted"
```

### Falco Rules
```yaml
- rule: Create ClusterRoleBinding
  desc: Detect creation of ClusterRoleBinding
  condition: kevt and ka and ka.verb=create and ka.target.resource=clusterrolebindings
  output: ClusterRoleBinding created (user=%ka.user.name verb=%ka.verb target=%ka.target.name)
  priority: WARNING
```

## Lab Environment

The lab creates a controlled environment with:

- Vulnerable ServiceAccount with limited permissions
- Role that allows creating RoleBindings
- Demonstration of privilege escalation
- Safe cleanup procedures

### Lab Commands
```bash
# Create lab environment
kubeshadow owasp k03 --lab --apply

# Run simulation
kubeshadow owasp k03 --lab --simulate

# Clean up (manual)
kubectl delete namespace rbac-lab
```

## Output Format

### JSON Structure
```json
{
  "graph": {
    "nodes": [
      {
        "id": "sa:default:my-sa",
        "type": "subject",
        "name": "my-sa",
        "namespace": "default"
      }
    ],
    "edges": [
      {
        "from": "sa:default:my-sa",
        "to": "role:default:my-role",
        "verb": "bind",
        "resource": "roles",
        "weight": 1
      }
    ]
  },
  "findings": [
    {
      "subject": "my-sa",
      "subjectType": "ServiceAccount",
      "namespace": "default",
      "role": "my-role",
      "roleType": "Role",
      "riskScore": 0.8,
      "severity": "HIGH",
      "escalationPaths": [...],
      "remediation": {...}
    }
  ]
}
```

## Security Considerations

- **Lab Mode Only**: Never use `--apply` in production
- **Read-Only Analysis**: Default mode is non-destructive
- **Privilege Requirements**: Requires cluster read permissions
- **Data Sensitivity**: RBAC data may contain sensitive information

## Integration

### CI/CD Pipeline
```yaml
- name: RBAC Security Scan
  run: kubeshadow owasp k03 --output rbac-report.json
```

### Monitoring
- Use Falco rules for real-time RBAC monitoring
- Set up alerts for ClusterRoleBinding creation
- Monitor for privilege escalation patterns

### Remediation Automation
- Use admission controllers to prevent dangerous bindings
- Implement least privilege policies
- Regular RBAC audits and reviews
