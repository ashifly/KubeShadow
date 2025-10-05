package rbac

import (
	"fmt"
	"math"
	"strings"

	"kubeshadow/pkg/logger"

	rbacv1 "k8s.io/api/rbac/v1"
)

// FindEscalationPaths finds all possible escalation paths from a subject to a target
func (s *RBACScanner) FindEscalationPaths(subject string, target ResourceAction) []EscalationPath {
	logger.Info("🔍 Finding escalation paths from %s to %s on %s", subject, target.Verb, target.Resource)

	// This is a simplified BFS implementation
	// In a real implementation, you'd use a proper graph library
	paths := []EscalationPath{}

	// For demonstration, we'll create some example paths
	// In reality, this would traverse the graph using BFS/Dijkstra

	// Example escalation path: ServiceAccount -> Role -> Resource
	examplePath := EscalationPath{
		Subject: subject,
		Target:  target,
		Steps: []PathStep{
			{
				From:     subject,
				To:       "role:default:example-role",
				Action:   "bind",
				Resource: "roles",
				Weight:   1,
			},
			{
				From:     "role:default:example-role",
				To:       fmt.Sprintf("resource:rbac.authorization.k8s.io:%s", target.Resource),
				Action:   target.Verb,
				Resource: target.Resource,
				Weight:   s.getVerbWeight(target.Verb),
			},
		},
		TotalWeight: 1 + s.getVerbWeight(target.Verb),
		RiskLevel:   s.calculateRiskLevel(1 + s.getVerbWeight(target.Verb)),
	}

	paths = append(paths, examplePath)

	return paths
}

// AnalyzeRBAC analyzes RBAC configuration for security issues
func (s *RBACScanner) AnalyzeRBAC(data *RBACData) []RBACFinding {
	logger.Info("🔍 Analyzing RBAC configuration for security issues...")

	findings := []RBACFinding{}

	// Analyze RoleBindings
	for _, rb := range data.RoleBindings {
		finding := s.analyzeRoleBinding(rb, data)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	// Analyze ClusterRoleBindings
	for _, crb := range data.ClusterRoleBindings {
		finding := s.analyzeClusterRoleBinding(crb, data)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	// Analyze for privilege escalation paths
	escalationFindings := s.findPrivilegeEscalationPaths(data)
	findings = append(findings, escalationFindings...)

	logger.Info("📊 Found %d RBAC security findings", len(findings))
	return findings
}

// analyzeRoleBinding analyzes a single RoleBinding
func (s *RBACScanner) analyzeRoleBinding(rb rbacv1.RoleBinding, data *RBACData) *RBACFinding {
	// Find the role
	var role *rbacv1.Role
	for _, r := range data.Roles {
		if r.Name == rb.RoleRef.Name && r.Namespace == rb.Namespace {
			role = &r
			break
		}
	}

	if role == nil {
		return nil
	}

	// Calculate risk score
	riskScore := s.calculateRoleRiskScore(role)

	// Check for dangerous permissions
	permissions := s.extractPermissions(role)
	hasDangerousPermissions := s.hasDangerousPermissions(permissions)

	if riskScore > 0.5 || hasDangerousPermissions {
		return &RBACFinding{
			Subject:     s.getSubjectString(rb.Subjects),
			SubjectType: "ServiceAccount",
			Namespace:   rb.Namespace,
			Role:        rb.RoleRef.Name,
			RoleType:    "Role",
			Permissions: permissions,
			RiskScore:   riskScore,
			Severity:    s.getSeverity(riskScore),
			Remediation: s.generateRemediation(role, "Role"),
		}
	}

	return nil
}

// analyzeClusterRoleBinding analyzes a single ClusterRoleBinding
func (s *RBACScanner) analyzeClusterRoleBinding(crb rbacv1.ClusterRoleBinding, data *RBACData) *RBACFinding {
	// Find the cluster role
	var clusterRole *rbacv1.ClusterRole
	for _, cr := range data.ClusterRoles {
		if cr.Name == crb.RoleRef.Name {
			clusterRole = &cr
			break
		}
	}

	if clusterRole == nil {
		return nil
	}

	// Calculate risk score
	riskScore := s.calculateClusterRoleRiskScore(clusterRole)

	// Check for dangerous permissions
	permissions := s.extractClusterRolePermissions(clusterRole)
	hasDangerousPermissions := s.hasDangerousPermissions(permissions)

	if riskScore > 0.3 || hasDangerousPermissions {
		return &RBACFinding{
			Subject:     s.getSubjectString(crb.Subjects),
			SubjectType: "ServiceAccount",
			Namespace:   "",
			Role:        crb.RoleRef.Name,
			RoleType:    "ClusterRole",
			Permissions: permissions,
			RiskScore:   riskScore,
			Severity:    s.getSeverity(riskScore),
			Remediation: s.generateRemediation(clusterRole, "ClusterRole"),
		}
	}

	return nil
}

// findPrivilegeEscalationPaths finds potential privilege escalation paths
func (s *RBACScanner) findPrivilegeEscalationPaths(data *RBACData) []RBACFinding {
	findings := []RBACFinding{}

	// Look for subjects that can create ClusterRoleBindings
	for _, crb := range data.ClusterRoleBindings {
		for _, subject := range crb.Subjects {
			if s.canCreateClusterRoleBinding(subject, data) {
				escalationPath := s.FindEscalationPaths(
					s.getSubjectID(subject, ""),
					ResourceAction{
						Resource: "clusterrolebindings",
						Verb:     "create",
					},
				)

				if len(escalationPath) > 0 {
					finding := RBACFinding{
						Subject:         s.getSubjectString([]rbacv1.Subject{subject}),
						SubjectType:     subject.Kind,
						Namespace:       "",
						Role:            crb.RoleRef.Name,
						RoleType:        "ClusterRole",
						RiskScore:       0.9,
						Severity:        "CRITICAL",
						EscalationPaths: escalationPath,
						Remediation:     s.generateEscalationRemediation(),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// calculateRoleRiskScore calculates the risk score for a role
func (s *RBACScanner) calculateRoleRiskScore(role *rbacv1.Role) float64 {
	score := 0.0

	for _, rule := range role.Rules {
		// Check for wildcard resources
		for _, resource := range rule.Resources {
			if resource == "*" {
				score += 0.5
			}
		}

		// Check for dangerous verbs
		for _, verb := range rule.Verbs {
			switch verb {
			case "*":
				score += 0.8
			case "create", "delete", "patch", "update":
				score += 0.3
			case "escalate", "impersonate":
				score += 0.9
			}
		}
	}

	return math.Min(score, 1.0)
}

// calculateClusterRoleRiskScore calculates the risk score for a cluster role
func (s *RBACScanner) calculateClusterRoleRiskScore(clusterRole *rbacv1.ClusterRole) float64 {
	score := 0.0

	// Cluster roles are inherently more dangerous
	score += 0.2

	for _, rule := range clusterRole.Rules {
		// Check for wildcard resources
		for _, resource := range rule.Resources {
			if resource == "*" {
				score += 0.6
			}
		}

		// Check for dangerous verbs
		for _, verb := range rule.Verbs {
			switch verb {
			case "*":
				score += 0.9
			case "create", "delete", "patch", "update":
				score += 0.4
			case "escalate", "impersonate":
				score += 1.0
			}
		}
	}

	return math.Min(score, 1.0)
}

// extractPermissions extracts permissions from a role
func (s *RBACScanner) extractPermissions(role *rbacv1.Role) []Permission {
	permissions := []Permission{}

	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			permission := Permission{
				Resource: resource,
				Verbs:    rule.Verbs,
				APIGroup: strings.Join(rule.APIGroups, ","),
			}
			permissions = append(permissions, permission)
		}
	}

	return permissions
}

// extractClusterRolePermissions extracts permissions from a cluster role
func (s *RBACScanner) extractClusterRolePermissions(clusterRole *rbacv1.ClusterRole) []Permission {
	permissions := []Permission{}

	for _, rule := range clusterRole.Rules {
		for _, resource := range rule.Resources {
			permission := Permission{
				Resource: resource,
				Verbs:    rule.Verbs,
				APIGroup: strings.Join(rule.APIGroups, ","),
			}
			permissions = append(permissions, permission)
		}
	}

	return permissions
}

// hasDangerousPermissions checks if permissions contain dangerous operations
func (s *RBACScanner) hasDangerousPermissions(permissions []Permission) bool {
	for _, perm := range permissions {
		for _, verb := range perm.Verbs {
			if verb == "*" || verb == "escalate" || verb == "impersonate" {
				return true
			}
		}
		if perm.Resource == "*" {
			return true
		}
	}
	return false
}

// canCreateClusterRoleBinding checks if a subject can create ClusterRoleBindings
func (s *RBACScanner) canCreateClusterRoleBinding(_ rbacv1.Subject, _ *RBACData) bool {
	// This is a simplified check
	// In reality, you'd need to traverse the full permission graph
	return false
}

// getSubjectString returns a string representation of subjects
func (s *RBACScanner) getSubjectString(subjects []rbacv1.Subject) string {
	if len(subjects) == 0 {
		return "unknown"
	}

	subject := subjects[0]
	return fmt.Sprintf("%s:%s", subject.Kind, subject.Name)
}

// getSeverity returns the severity level based on risk score
func (s *RBACScanner) getSeverity(riskScore float64) string {
	if riskScore >= 0.8 {
		return "CRITICAL"
	} else if riskScore >= 0.6 {
		return "HIGH"
	} else if riskScore >= 0.4 {
		return "MEDIUM"
	} else {
		return "LOW"
	}
}

// calculateRiskLevel calculates risk level based on path weight
func (s *RBACScanner) calculateRiskLevel(weight int) string {
	if weight >= 8 {
		return "CRITICAL"
	} else if weight >= 5 {
		return "HIGH"
	} else if weight >= 3 {
		return "MEDIUM"
	} else {
		return "LOW"
	}
}

// generateRemediation generates remediation suggestions
func (s *RBACScanner) generateRemediation(_ interface{}, roleType string) Remediation {
	return Remediation{
		Description: fmt.Sprintf("Review and apply least privilege principle to %s", roleType),
		LeastPrivilege: []string{
			"Remove wildcard permissions (*)",
			"Use specific resource names instead of *",
			"Remove unnecessary verbs",
			"Consider using built-in roles when possible",
		},
		FalcoRules: []string{
			"Alert on new ClusterRoleBinding creation",
			"Alert on role escalation attempts",
			"Monitor for privilege escalation patterns",
		},
		KubectlApply: s.generateKubectlRemediation(roleType),
	}
}

// generateEscalationRemediation generates remediation for escalation paths
func (s *RBACScanner) generateEscalationRemediation() Remediation {
	return Remediation{
		Description: "Privilege escalation path detected - immediate review required",
		LeastPrivilege: []string{
			"Remove ClusterRoleBinding creation permissions",
			"Implement admission controllers to prevent privilege escalation",
			"Use RBAC policies to restrict role binding",
		},
		FalcoRules: []string{
			"Alert on ClusterRoleBinding creation",
			"Alert on role escalation attempts",
			"Monitor for privilege escalation patterns",
		},
		KubectlApply: `# Apply admission controller to prevent privilege escalation
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-policy
  namespace: kube-system
data:
  policy.yaml: |
    apiVersion: v1
    kind: Policy
    rules:
    - level: Error
      users: ["*"]
      verbs: ["create", "update", "patch"]
      resources: ["clusterrolebindings"]
      message: "ClusterRoleBinding creation is restricted"
EOF`,
	}
}

// generateKubectlRemediation generates kubectl apply commands for remediation
func (s *RBACScanner) generateKubectlRemediation(roleType string) string {
	return fmt.Sprintf(`# Example least privilege %s
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: %s
metadata:
  name: secure-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
EOF`, roleType, roleType)
}
