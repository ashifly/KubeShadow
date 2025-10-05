package policy

import (
	"context"
	"fmt"
	"strings"

	"kubeshadow/pkg/logger"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RunPolicySimulation runs a policy evaluation simulation
func (s *PolicyScanner) RunPolicySimulation(ctx context.Context, findings []PolicyFinding) error {
	logger.Info("🧪 Starting policy evaluation simulation...")
	logger.Info("⚠️  This is a SIMULATION - evaluating policies against sample manifests")

	// Generate sample manifests for testing
	sampleManifests := s.generateSampleManifests()

	// Evaluate each manifest against policies
	for _, manifest := range sampleManifests {
		evaluation := s.evaluateManifest(manifest)
		s.displayEvaluation(manifest, evaluation)
	}

	logger.Info("")
	logger.Info("💡 This demonstrates how policies would block dangerous configurations:")
	logger.Info("   • Pod Security Standards prevent privileged containers")
	logger.Info("   • Network policies restrict traffic")
	logger.Info("   • Resource quotas prevent resource exhaustion")
	logger.Info("   • Image policies enforce security requirements")
	logger.Info("")

	logger.Info("🛡️  Real-world protection requires:")
	logger.Info("   • Centralized policy enforcement")
	logger.Info("   • Admission controllers")
	logger.Info("   • Regular policy audits")
	logger.Info("   • Policy testing and validation")

	return nil
}

// generateSampleManifests generates sample manifests for policy testing
func (s *PolicyScanner) generateSampleManifests() []string {
	return []string{
		`# Dangerous Pod - Should be blocked
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
  namespace: default
spec:
  containers:
  - name: dangerous
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true`,

		`# Service with External IP - Should be restricted
apiVersion: v1
kind: Service
metadata:
  name: external-service
  namespace: default
spec:
  type: LoadBalancer
  externalIPs:
  - 1.2.3.4
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: nginx`,

		`# Secret with plaintext - Should be encrypted
apiVersion: v1
kind: Secret
metadata:
  name: plaintext-secret
  namespace: default
type: Opaque
data:
  password: cGFzc3dvcmQ=  # base64 encoded "password"`,

		`# Deployment without resource limits - Should have limits
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unlimited-deployment
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: unlimited
  template:
    metadata:
      labels:
        app: unlimited
    spec:
      containers:
      - name: unlimited
        image: nginx:latest
        # No resource limits specified`,

		`# Pod without security context - Should be restricted
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: default
spec:
  containers:
  - name: insecure
    image: nginx:latest
    # No security context specified`,
	}
}

// evaluateManifest evaluates a manifest against policies
func (s *PolicyScanner) evaluateManifest(manifest string) PolicyEvaluation {
	evaluation := PolicyEvaluation{
		Manifest:          manifest,
		Violations:        []PolicyViolation{},
		Allowed:           true,
		EnforcementAction: "allow",
		PolicyEngine:      "simulation",
	}

	// Simulate policy evaluation based on manifest content
	lines := strings.Split(manifest, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Check for privileged containers
		if strings.Contains(line, "privileged: true") {
			evaluation.Violations = append(evaluation.Violations, PolicyViolation{
				Policy:   "pod-security-standard",
				Rule:     "no-privileged",
				Message:  "Privileged containers are not allowed",
				Severity: "CRITICAL",
				Resource: "Pod",
				Field:    fmt.Sprintf("line %d", i+1),
			})
			evaluation.Allowed = false
		}

		// Check for hostPath volumes
		if strings.Contains(line, "hostPath:") {
			evaluation.Violations = append(evaluation.Violations, PolicyViolation{
				Policy:   "no-hostpath",
				Rule:     "no-hostpath-volumes",
				Message:  "HostPath volumes are not allowed",
				Severity: "HIGH",
				Resource: "Pod",
				Field:    fmt.Sprintf("line %d", i+1),
			})
			evaluation.Allowed = false
		}

		// Check for hostNetwork
		if strings.Contains(line, "hostNetwork: true") {
			evaluation.Violations = append(evaluation.Violations, PolicyViolation{
				Policy:   "pod-security-standard",
				Rule:     "no-host-network",
				Message:  "Host network is not allowed",
				Severity: "HIGH",
				Resource: "Pod",
				Field:    fmt.Sprintf("line %d", i+1),
			})
			evaluation.Allowed = false
		}

		// Check for runAsUser: 0
		if strings.Contains(line, "runAsUser: 0") {
			evaluation.Violations = append(evaluation.Violations, PolicyViolation{
				Policy:   "pod-security-standard",
				Rule:     "no-root",
				Message:  "Running as root is not allowed",
				Severity: "HIGH",
				Resource: "Pod",
				Field:    fmt.Sprintf("line %d", i+1),
			})
			evaluation.Allowed = false
		}

		// Check for external IPs
		if strings.Contains(line, "externalIPs:") {
			evaluation.Violations = append(evaluation.Violations, PolicyViolation{
				Policy:   "no-external-ips",
				Rule:     "no-external-ips",
				Message:  "External IPs are not allowed",
				Severity: "MEDIUM",
				Resource: "Service",
				Field:    fmt.Sprintf("line %d", i+1),
			})
			evaluation.Allowed = false
		}

		// Check for missing resource limits
		if strings.Contains(line, "image:") && !strings.Contains(manifest, "resources:") {
			evaluation.Violations = append(evaluation.Violations, PolicyViolation{
				Policy:   "resource-limits",
				Rule:     "require-resource-limits",
				Message:  "Resource limits are required",
				Severity: "MEDIUM",
				Resource: "Pod",
				Field:    "spec.containers[].resources",
			})
		}
	}

	if !evaluation.Allowed {
		evaluation.EnforcementAction = "deny"
	}

	return evaluation
}

// displayEvaluation displays the policy evaluation results
func (s *PolicyScanner) displayEvaluation(manifest string, evaluation PolicyEvaluation) {
	// Extract resource type and name from manifest
	lines := strings.Split(manifest, "\n")
	resourceType := "Unknown"
	resourceName := "unknown"

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "kind:") {
			resourceType = strings.TrimSpace(strings.TrimPrefix(line, "kind:"))
		}
		if strings.HasPrefix(line, "name:") {
			resourceName = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		}
	}

	logger.Info("📋 Policy Evaluation: %s/%s", resourceType, resourceName)

	if evaluation.Allowed {
		logger.Info("   ✅ ALLOWED - No policy violations")
	} else {
		logger.Info("   ❌ BLOCKED - %d policy violations", len(evaluation.Violations))

		for _, violation := range evaluation.Violations {
			logger.Info("      • %s: %s (%s)", violation.Policy, violation.Message, violation.Severity)
		}
	}

	logger.Info("")
}

// GeneratePolicyTestSuite generates a comprehensive policy test suite
func (s *PolicyScanner) GeneratePolicyTestSuite() string {
	return `#!/bin/bash
# Policy Test Suite for Kubernetes
# This script tests various policy scenarios

echo "🧪 Kubernetes Policy Test Suite"
echo "================================"
echo ""

# Test 1: Pod Security Standards
echo "📋 Test 1: Pod Security Standards"
echo "Testing privileged container rejection..."

cat << 'EOF' | kubectl apply -f - || echo "✅ Correctly blocked privileged pod"
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: default
spec:
  containers:
  - name: test
    image: nginx:latest
    securityContext:
      privileged: true
EOF

echo ""

# Test 2: Resource Limits
echo "📋 Test 2: Resource Limits"
echo "Testing resource limit enforcement..."

cat << 'EOF' | kubectl apply -f - || echo "✅ Correctly blocked pod without limits"
apiVersion: v1
kind: Pod
metadata:
  name: test-no-limits
  namespace: default
spec:
  containers:
  - name: test
    image: nginx:latest
    # No resource limits
EOF

echo ""

# Test 3: Network Policies
echo "📋 Test 3: Network Policies"
echo "Testing network policy enforcement..."

cat << 'EOF' | kubectl apply -f - || echo "✅ Correctly blocked external IP service"
apiVersion: v1
kind: Service
metadata:
  name: test-external
  namespace: default
spec:
  type: LoadBalancer
  externalIPs:
  - 1.2.3.4
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: nginx
EOF

echo ""

# Test 4: Image Security
echo "📋 Test 4: Image Security"
echo "Testing image security policies..."

cat << 'EOF' | kubectl apply -f - || echo "✅ Correctly blocked unsigned image"
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned
  namespace: default
spec:
  containers:
  - name: test
    image: untrusted-registry.com/nginx:latest
EOF

echo ""
echo "🎯 Policy Test Results:"
echo "• Check the output above for policy enforcement"
echo "• 'Correctly blocked' messages indicate working policies"
echo "• Successful applies indicate missing policies"
echo ""
echo "🛡️  Recommended Actions:"
echo "1. Install a policy engine (Gatekeeper, OPA, or Kyverno)"
echo "2. Apply Pod Security Standards"
echo "3. Configure network policies"
echo "4. Set up resource quotas"
echo "5. Enable image signing verification"
`
}

// CreatePolicyLabEnvironment creates a lab environment for policy testing
func (s *PolicyScanner) CreatePolicyLabEnvironment(ctx context.Context) error {
	logger.Info("🏗️  Creating policy lab environment...")

	// Create namespace for lab
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-lab",
			Labels: map[string]string{
				"kubeshadow.io/lab":                  "policy",
				"pod-security.kubernetes.io/enforce": "restricted",
				"pod-security.kubernetes.io/audit":   "restricted",
				"pod-security.kubernetes.io/warn":    "restricted",
			},
		},
	}

	_, err := s.client.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create namespace: %v", err)
	}

	// Create resource quota
	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-lab-quota",
			Namespace: "policy-lab",
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				"pods":            resource.MustParse("10"),
				"requests.cpu":    resource.MustParse("2"),
				"requests.memory": resource.MustParse("4Gi"),
				"limits.cpu":      resource.MustParse("4"),
				"limits.memory":   resource.MustParse("8Gi"),
			},
		},
	}

	_, err = s.client.CoreV1().ResourceQuotas("policy-lab").Create(ctx, quota, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create resource quota: %v", err)
	}

	// Create network policy
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-lab-netpol",
			Namespace: "policy-lab",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "allowed",
								},
							},
						},
					},
				},
			},
		},
	}

	_, err = s.client.NetworkingV1().NetworkPolicies("policy-lab").Create(ctx, networkPolicy, metav1.CreateOptions{})
	if err != nil {
		logger.Warn("Failed to create network policy: %v", err)
	}

	logger.Info("✅ Policy lab environment created in namespace 'policy-lab'")
	logger.Info("   • Pod Security Standards enabled")
	logger.Info("   • Resource quotas configured")
	logger.Info("   • Network policies applied")

	return nil
}

// CleanupPolicyLabEnvironment cleans up the policy lab environment
func (s *PolicyScanner) CleanupPolicyLabEnvironment(ctx context.Context) error {
	logger.Info("🧹 Cleaning up policy lab environment...")

	// Delete namespace (this will cascade delete all resources)
	err := s.client.CoreV1().Namespaces().Delete(ctx, "policy-lab", metav1.DeleteOptions{})
	if err != nil {
		logger.Warn("Failed to delete namespace: %v", err)
	}

	logger.Info("✅ Policy lab environment cleaned up")
	return nil
}
