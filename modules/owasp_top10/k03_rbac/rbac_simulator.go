package rbac

import (
	"context"
	"fmt"

	"kubeshadow/pkg/logger"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RunSimulation runs a non-destructive RBAC simulation
func (s *RBACScanner) RunSimulation(ctx context.Context, findings []RBACFinding) error {
	logger.Info("🧪 Starting RBAC privilege escalation simulation...")
	logger.Info("⚠️  This is a SIMULATION - no actual changes will be made")

	// Generate simulation manifests
	simulationManifests := s.generateSimulationManifests(findings)

	logger.Info("📄 RBAC Privilege Escalation Simulation Manifests:")
	logger.Info("")
	logger.Info("%s", simulationManifests)
	logger.Info("")

	logger.Info("💡 This demonstrates how privilege escalation could occur:")
	logger.Info("   1. Attacker gains access to a ServiceAccount with limited permissions")
	logger.Info("   2. ServiceAccount has permission to create RoleBindings")
	logger.Info("   3. Attacker creates a RoleBinding to a powerful ClusterRole")
	logger.Info("   4. Attacker now has elevated privileges")
	logger.Info("")

	logger.Info("🛡️  Real-world protection requires:")
	logger.Info("   • Regular RBAC audits")
	logger.Info("   • Least privilege principle")
	logger.Info("   • Admission controllers to prevent privilege escalation")
	logger.Info("   • Monitoring and alerting on RBAC changes")

	return nil
}

// generateSimulationManifests generates manifests for simulation
func (s *RBACScanner) generateSimulationManifests(findings []RBACFinding) string {
	manifests := `# RBAC Privilege Escalation Simulation
# This demonstrates how an attacker could escalate privileges

# Step 1: Vulnerable ServiceAccount with limited permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnerable-sa
  namespace: default
---
# Step 2: Role that allows creating RoleBindings (vulnerable!)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: role-binder
  namespace: default
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings"]
  verbs: ["create", "update", "patch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["get", "list"]
---
# Step 3: RoleBinding that gives the SA the vulnerable role
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vulnerable-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: vulnerable-sa
  namespace: default
roleRef:
  kind: Role
  name: role-binder
  apiGroup: rbac.authorization.k8s.io
---
# Step 4: Powerful ClusterRole that the attacker wants to bind to
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: powerful-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "secrets"]
  verbs: ["*"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["*"]
---
# Step 5: The escalation - attacker creates binding to powerful role
# This is what the attacker would do:
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: escalation-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: vulnerable-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: powerful-role
  apiGroup: rbac.authorization.k8s.io
---
# Step 6: Pod that uses the escalated ServiceAccount
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  serviceAccountName: vulnerable-sa
  containers:
  - name: attacker
    image: alpine:latest
    command: ["sh", "-c"]
    args:
    - echo "I now have escalated privileges!"
    - echo "I can access secrets, create pods, etc."
    - sleep 3600
`

	// Add specific findings to the simulation
	if len(findings) > 0 {
		manifests += "\n# Specific findings from your cluster:\n"
		for i, finding := range findings {
			if i >= 3 { // Limit to first 3 findings
				break
			}
			manifests += fmt.Sprintf("# Finding %d: %s has %s role with risk score %.2f\n",
				i+1, finding.Subject, finding.Role, finding.RiskScore)
		}
	}

	return manifests
}

// GenerateEscalationScript generates a script to demonstrate escalation
func (s *RBACScanner) GenerateEscalationScript(findings []RBACFinding) string {
	script := `#!/bin/bash
# RBAC Privilege Escalation Demonstration Script
# This script demonstrates how privilege escalation could occur

echo "🔍 RBAC Privilege Escalation Demonstration"
echo "========================================"
echo ""

echo "📊 Current RBAC State:"
kubectl get serviceaccounts -o wide
kubectl get roles,rolebindings,clusterroles,clusterrolebindings
echo ""

echo "🎯 Step 1: Identify vulnerable ServiceAccount"
echo "Looking for ServiceAccounts with role-binding permissions..."
kubectl get rolebindings -o jsonpath='{range .items[*]}{.subjects[*].name}{" "}{.roleRef.name}{"\\n"}{end}'
echo ""

echo "🎯 Step 2: Check what permissions the ServiceAccount has"
echo "Analyzing permissions for vulnerable ServiceAccount..."
kubectl auth can-i --list --as=system:serviceaccount:default:vulnerable-sa
echo ""

echo "🎯 Step 3: Attempt privilege escalation"
echo "Creating RoleBinding to powerful ClusterRole..."
echo "kubectl create rolebinding escalation-binding \\"
echo "  --clusterrole=powerful-role \\"
echo "  --serviceaccount=default:vulnerable-sa \\"
echo "  --namespace=default"
echo ""

echo "🎯 Step 4: Verify escalated permissions"
echo "Checking new permissions after escalation..."
echo "kubectl auth can-i --list --as=system:serviceaccount:default:vulnerable-sa"
echo ""

echo "🛡️  Prevention measures:"
echo "1. Use admission controllers to prevent privilege escalation"
echo "2. Implement least privilege principle"
echo "3. Regular RBAC audits"
echo "4. Monitor for RBAC changes"
echo "5. Use Falco rules to alert on suspicious activity"
echo ""

echo "📋 Falco Rules for RBAC Monitoring:"
cat << 'EOF'
- rule: Create ClusterRoleBinding
  desc: Detect creation of ClusterRoleBinding
  condition: kevt and ka and ka.verb=create and ka.target.resource=clusterrolebindings
  output: ClusterRoleBinding created (user=%ka.user.name verb=%ka.verb target=%ka.target.name)
  priority: WARNING

- rule: Create RoleBinding to ClusterRole
  desc: Detect RoleBinding to ClusterRole (potential escalation)
  condition: kevt and ka and ka.verb=create and ka.target.resource=rolebindings and ka.target.name contains "cluster"
  output: RoleBinding to ClusterRole created (user=%ka.user.name target=%ka.target.name)
  priority: WARNING
EOF
`

	return script
}

// CreateLabEnvironment creates a lab environment for testing
func (s *RBACScanner) CreateLabEnvironment(ctx context.Context) error {
	logger.Info("🏗️  Creating RBAC lab environment...")

	// Create namespace for lab
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rbac-lab",
			Labels: map[string]string{
				"kubeshadow.io/lab": "rbac",
			},
		},
	}

	_, err := s.client.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create namespace: %v", err)
	}

	// Create vulnerable ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vulnerable-sa",
			Namespace: "rbac-lab",
		},
	}

	_, err = s.client.CoreV1().ServiceAccounts("rbac-lab").Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create ServiceAccount: %v", err)
	}

	// Create vulnerable Role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "role-binder",
			Namespace: "rbac-lab",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"create", "update", "patch"},
			},
		},
	}

	_, err = s.client.RbacV1().Roles("rbac-lab").Create(ctx, role, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create Role: %v", err)
	}

	// Create RoleBinding
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vulnerable-binding",
			Namespace: "rbac-lab",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "vulnerable-sa",
				Namespace: "rbac-lab",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "role-binder",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	_, err = s.client.RbacV1().RoleBindings("rbac-lab").Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create RoleBinding: %v", err)
	}

	logger.Info("✅ RBAC lab environment created in namespace 'rbac-lab'")
	return nil
}

// CleanupLabEnvironment cleans up the lab environment
func (s *RBACScanner) CleanupLabEnvironment(ctx context.Context) error {
	logger.Info("🧹 Cleaning up RBAC lab environment...")

	// Delete namespace (this will cascade delete all resources)
	err := s.client.CoreV1().Namespaces().Delete(ctx, "rbac-lab", metav1.DeleteOptions{})
	if err != nil {
		logger.Warn("Failed to delete namespace: %v", err)
	}

	logger.Info("✅ RBAC lab environment cleaned up")
	return nil
}
