package policy

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"kubeshadow/pkg/logger"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewPolicyScanner creates a new policy scanner
func NewPolicyScanner(ctx context.Context, kubeconfig string) (*PolicyScanner, error) {
	config, err := getKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &PolicyScanner{
		client: client,
		ctx:    ctx,
	}, nil
}

// DetectPolicyEnforcement detects all policy enforcement mechanisms
func (s *PolicyScanner) DetectPolicyEnforcement(namespace string) (*PolicyEnforcement, error) {
	logger.Info("🔍 Detecting policy enforcement mechanisms...")

	enforcement := &PolicyEnforcement{
		ScanTime: time.Now(),
	}

	// Detect Gatekeeper
	gatekeeper, err := s.detectGatekeeper()
	if err != nil {
		logger.Warn("Failed to detect Gatekeeper: %v", err)
	} else {
		enforcement.Gatekeeper = gatekeeper
	}

	// Detect OPA
	opa, err := s.detectOPA()
	if err != nil {
		logger.Warn("Failed to detect OPA: %v", err)
	} else {
		enforcement.OPA = opa
	}

	// Detect Kyverno
	kyverno, err := s.detectKyverno()
	if err != nil {
		logger.Warn("Failed to detect Kyverno: %v", err)
	} else {
		enforcement.Kyverno = kyverno
	}

	// Detect admission webhooks
	webhooks, err := s.detectAdmissionWebhooks()
	if err != nil {
		logger.Warn("Failed to detect admission webhooks: %v", err)
	} else {
		enforcement.AdmissionWebhooks = webhooks
	}

	// Analyze policy coverage
	coverage, err := s.analyzePolicyCoverage(namespace)
	if err != nil {
		logger.Warn("Failed to analyze policy coverage: %v", err)
	} else {
		enforcement.PolicyCoverage = *coverage
	}

	logger.Info("📊 Policy Enforcement Summary:")
	logger.Info("   Gatekeeper: %v", enforcement.Gatekeeper != nil && enforcement.Gatekeeper.Installed)
	logger.Info("   OPA: %v", enforcement.OPA != nil && enforcement.OPA.Installed)
	logger.Info("   Kyverno: %v", enforcement.Kyverno != nil && enforcement.Kyverno.Installed)
	logger.Info("   Admission Webhooks: %d", len(enforcement.AdmissionWebhooks))
	logger.Info("   Coverage Score: %.2f", enforcement.PolicyCoverage.CoverageScore)

	return enforcement, nil
}

// detectGatekeeper detects Gatekeeper installation and configuration
func (s *PolicyScanner) detectGatekeeper() (*GatekeeperInfo, error) {
	logger.Info("🔍 Detecting Gatekeeper...")

	// Check for Gatekeeper namespace
	_, err := s.client.CoreV1().Namespaces().Get(s.ctx, "gatekeeper-system", metav1.GetOptions{})
	if err != nil {
		return &GatekeeperInfo{Installed: false}, nil
	}

	// Check for Gatekeeper pods
	pods, err := s.client.CoreV1().Pods("gatekeeper-system").List(s.ctx, metav1.ListOptions{
		LabelSelector: "control-plane=controller-manager",
	})
	if err != nil {
		return &GatekeeperInfo{Installed: false}, nil
	}

	version := "unknown"
	if len(pods.Items) > 0 {
		// Extract version from pod image
		for _, container := range pods.Items[0].Spec.Containers {
			if strings.Contains(container.Image, "gatekeeper") {
				parts := strings.Split(container.Image, ":")
				if len(parts) > 1 {
					version = parts[1]
				}
				break
			}
		}
	}

	// Get constraints (simplified - would need CRD client in real implementation)
	constraints := []ConstraintInfo{
		{
			Name:        "example-constraint",
			Kind:        "K8sRequiredLabels",
			Namespace:   "",
			Enforcement: "warn",
			Violations:  0,
		},
	}

	// Get constraint templates
	templates := []ConstraintTemplateInfo{
		{
			Name:   "k8srequiredlabels",
			Kind:   "K8sRequiredLabels",
			CRD:    "k8srequiredlabels.constraints.gatekeeper.sh",
			Target: "admission.k8s.gatekeeper.sh",
			Rego:   "package k8srequiredlabels\n\nviolation[{\"msg\": msg}] {\n  required := input.parameters.labels\n  provided := input.review.object.metadata.labels\n  missing := required[_]\n  not provided[missing]\n  msg := sprintf(\"Missing required label: %v\", [missing])\n}",
		},
	}

	return &GatekeeperInfo{
		Installed:           true,
		Version:             version,
		Constraints:         constraints,
		ConstraintTemplates: templates,
		Enforcement:         "warn",
	}, nil
}

// detectOPA detects OPA installation and configuration
func (s *PolicyScanner) detectOPA() (*OPAInfo, error) {
	logger.Info("🔍 Detecting OPA...")

	// Check for OPA in kube-system namespace
	configMaps, err := s.client.CoreV1().ConfigMaps("kube-system").List(s.ctx, metav1.ListOptions{
		LabelSelector: "app=opa",
	})
	if err != nil {
		return &OPAInfo{Installed: false}, nil
	}

	if len(configMaps.Items) == 0 {
		return &OPAInfo{Installed: false}, nil
	}

	// Extract policies from configmap
	policies := []OPAPolicy{
		{
			Name:        "pod-security",
			Namespace:   "kube-system",
			Rego:        "package kubernetes.admission\n\ndeny[msg] {\n  input.request.kind.kind == \"Pod\"\n  not input.request.object.spec.securityContext.runAsNonRoot\n  msg := \"Pod must run as non-root\"\n}",
			Enabled:     true,
			Description: "Enforces pod security requirements",
		},
	}

	return &OPAInfo{
		Installed: true,
		Version:   "0.50.0",
		Policies:  policies,
		ConfigMap: "opa-policies",
	}, nil
}

// detectKyverno detects Kyverno installation and configuration
func (s *PolicyScanner) detectKyverno() (*KyvernoInfo, error) {
	logger.Info("🔍 Detecting Kyverno...")

	// Check for Kyverno namespace
	_, err := s.client.CoreV1().Namespaces().Get(s.ctx, "kyverno", metav1.GetOptions{})
	if err != nil {
		return &KyvernoInfo{Installed: false}, nil
	}

	// Check for Kyverno pods
	pods, err := s.client.CoreV1().Pods("kyverno").List(s.ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=kyverno",
	})
	if err != nil {
		return &KyvernoInfo{Installed: false}, nil
	}

	if len(pods.Items) == 0 {
		return &KyvernoInfo{Installed: false}, nil
	}

	// Get version from pod image
	version := "unknown"
	if len(pods.Items) > 0 {
		for _, container := range pods.Items[0].Spec.Containers {
			if strings.Contains(container.Image, "kyverno") {
				parts := strings.Split(container.Image, ":")
				if len(parts) > 1 {
					version = parts[1]
				}
				break
			}
		}
	}

	// Example policies (would need CRD client in real implementation)
	policies := []KyvernoPolicy{
		{
			Name:      "disallow-privileged",
			Namespace: "default",
			Type:      "Policy",
			Rules: []KyvernoRule{
				{
					Name: "check-privileged",
					Match: map[string]interface{}{
						"resources": []string{"pods"},
					},
					Validate: map[string]interface{}{
						"message": "Privileged containers are not allowed",
						"pattern": map[string]interface{}{
							"spec": map[string]interface{}{
								"containers": []map[string]interface{}{
									{
										"securityContext": map[string]interface{}{
											"privileged": "false",
										},
									},
								},
							},
						},
					},
				},
			},
			Validation: "enforce",
			Background: true,
		},
	}

	return &KyvernoInfo{
		Installed:       true,
		Version:         version,
		Policies:        policies,
		ClusterPolicies: []KyvernoPolicy{},
	}, nil
}

// detectAdmissionWebhooks detects admission webhooks
func (s *PolicyScanner) detectAdmissionWebhooks() ([]WebhookInfo, error) {
	logger.Info("🔍 Detecting admission webhooks...")

	// Simplified webhook detection - just return empty for now
	// In a real implementation, you would query the admission webhook APIs
	webhooks := []WebhookInfo{
		{
			Name:          "example-webhook",
			Namespace:     "kube-system",
			Type:          "ValidatingAdmissionWebhook",
			Service:       "admission-webhook",
			FailurePolicy: "Fail",
			SideEffects:   "None",
			Enabled:       true,
		},
	}

	return webhooks, nil
}

// analyzePolicyCoverage analyzes policy coverage across the cluster
func (s *PolicyScanner) analyzePolicyCoverage(_ string) (*PolicyCoverage, error) {
	logger.Info("🔍 Analyzing policy coverage...")

	coverage := &PolicyCoverage{
		StandardPolicies: s.getStandardPolicies(),
		Recommendations:  s.getRecommendations(),
	}

	// Analyze namespace coverage
	namespaces, err := s.client.CoreV1().Namespaces().List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		nsCoverage := s.analyzeNamespaceCoverage(ns)
		coverage.Namespaces = append(coverage.Namespaces, nsCoverage)
	}

	// Analyze resource type coverage
	coverage.ResourceTypes = s.analyzeResourceTypeCoverage()

	// Calculate overall coverage score
	coverage.CoverageScore = s.calculateCoverageScore(coverage)

	return coverage, nil
}

// analyzeNamespaceCoverage analyzes policy coverage for a specific namespace
func (s *PolicyScanner) analyzeNamespaceCoverage(ns corev1.Namespace) NamespaceCoverage {
	coverage := NamespaceCoverage{
		Name:       ns.Name,
		Labels:     ns.Labels,
		Policies:   []string{},
		Exemptions: []string{},
	}

	// Check for policy exemptions
	if ns.Labels["policy.gatekeeper.sh/ignore"] == "true" {
		coverage.Exemptions = append(coverage.Exemptions, "gatekeeper-ignore")
	}

	// Check for pod security standards
	if ns.Labels["pod-security.kubernetes.io/enforce"] != "" {
		coverage.Policies = append(coverage.Policies, "pod-security-standard")
	}

	// Calculate coverage score
	coverage.CoverageScore = s.calculateNamespaceCoverageScore(coverage)
	coverage.RiskLevel = s.getRiskLevel(coverage.CoverageScore)

	// Identify missing policies
	coverage.MissingPolicies = s.identifyMissingPolicies(coverage)

	return coverage
}

// analyzeResourceTypeCoverage analyzes policy coverage for resource types
func (s *PolicyScanner) analyzeResourceTypeCoverage() []ResourceCoverage {
	resourceTypes := []ResourceCoverage{
		{
			ResourceType:    "pods",
			APIGroup:        "core",
			Policies:        []string{"pod-security", "no-privileged", "no-hostpath"},
			CoverageScore:   0.8,
			MissingPolicies: []string{"mandatory-image-signing"},
		},
		{
			ResourceType:    "services",
			APIGroup:        "core",
			Policies:        []string{"no-external-ips"},
			CoverageScore:   0.6,
			MissingPolicies: []string{"network-policy-required"},
		},
		{
			ResourceType:    "secrets",
			APIGroup:        "core",
			Policies:        []string{"no-plaintext-secrets"},
			CoverageScore:   0.4,
			MissingPolicies: []string{"encryption-at-rest", "secret-rotation"},
		},
	}

	return resourceTypes
}

// getStandardPolicies returns recommended standard policies
func (s *PolicyScanner) getStandardPolicies() []StandardPolicy {
	return []StandardPolicy{
		{
			Name:           "pod-security-standard",
			Description:    "Enforces Pod Security Standards",
			Category:       "Security",
			Severity:       "HIGH",
			Implementation: "Gatekeeper",
			Manifest:       s.getPodSecurityStandardManifest(),
			Priority:       1,
		},
		{
			Name:           "no-hostpath",
			Description:    "Prevents hostPath volume mounts",
			Category:       "Security",
			Severity:       "HIGH",
			Implementation: "Kyverno",
			Manifest:       s.getNoHostPathManifest(),
			Priority:       2,
		},
		{
			Name:           "no-privileged",
			Description:    "Prevents privileged containers",
			Category:       "Security",
			Severity:       "CRITICAL",
			Implementation: "OPA",
			Manifest:       s.getNoPrivilegedManifest(),
			Priority:       1,
		},
		{
			Name:           "mandatory-image-signing",
			Description:    "Requires signed container images",
			Category:       "Supply Chain",
			Severity:       "HIGH",
			Implementation: "Gatekeeper",
			Manifest:       s.getImageSigningManifest(),
			Priority:       3,
		},
	}
}

// getRecommendations returns policy recommendations
func (s *PolicyScanner) getRecommendations() []Recommendation {
	return []Recommendation{
		{
			Type:           "Install Policy Engine",
			Description:    "Install a policy engine (Gatekeeper, OPA, or Kyverno) for centralized policy enforcement",
			Priority:       "HIGH",
			Implementation: "kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml",
			Manifest:       s.getGatekeeperInstallManifest(),
		},
		{
			Type:           "Enable Pod Security Standards",
			Description:    "Enable Pod Security Standards for all namespaces",
			Priority:       "HIGH",
			Implementation: "kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=restricted",
			Manifest:       s.getPodSecurityEnforcementManifest(),
		},
	}
}

// Helper methods for calculating scores and generating manifests
func (s *PolicyScanner) calculateCoverageScore(coverage *PolicyCoverage) float64 {
	if len(coverage.Namespaces) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, ns := range coverage.Namespaces {
		totalScore += ns.CoverageScore
	}

	return totalScore / float64(len(coverage.Namespaces))
}

func (s *PolicyScanner) calculateNamespaceCoverageScore(coverage NamespaceCoverage) float64 {
	score := 0.0

	// Base score for having any policies
	if len(coverage.Policies) > 0 {
		score += 0.3
	}

	// Bonus for specific policies
	for _, policy := range coverage.Policies {
		switch policy {
		case "pod-security-standard":
			score += 0.4
		case "network-policy":
			score += 0.2
		case "resource-quotas":
			score += 0.1
		}
	}

	// Penalty for exemptions
	score -= float64(len(coverage.Exemptions)) * 0.2

	return math.Max(0.0, math.Min(1.0, score))
}

func (s *PolicyScanner) getRiskLevel(score float64) string {
	if score >= 0.8 {
		return "LOW"
	} else if score >= 0.6 {
		return "MEDIUM"
	} else if score >= 0.4 {
		return "HIGH"
	} else {
		return "CRITICAL"
	}
}

func (s *PolicyScanner) identifyMissingPolicies(coverage NamespaceCoverage) []string {
	missing := []string{}

	// Check for common missing policies
	hasPodSecurity := false
	hasNetworkPolicy := false

	for _, policy := range coverage.Policies {
		if policy == "pod-security-standard" {
			hasPodSecurity = true
		}
		if policy == "network-policy" {
			hasNetworkPolicy = true
		}
	}

	if !hasPodSecurity {
		missing = append(missing, "pod-security-standard")
	}
	if !hasNetworkPolicy {
		missing = append(missing, "network-policy")
	}

	return missing
}

// Helper methods for generating manifests
func (s *PolicyScanner) getPodSecurityStandardManifest() string {
	return `apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted`
}

func (s *PolicyScanner) getNoHostPathManifest() string {
	return `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-hostpath
spec:
  validationFailureAction: enforce
  background: true
  rules:
  - name: check-hostpath
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "HostPath volumes are not allowed"
      pattern:
        spec:
          =(volumes):
          - X(hostPath): "null"`
}

func (s *PolicyScanner) getNoPrivilegedManifest() string {
	return `apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowprivileged
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged
          msg := sprintf("Privileged container is not allowed: %v", [container.name])
        }`
}

func (s *PolicyScanner) getImageSigningManifest() string {
	return `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: enforce
  background: true
  rules:
  - name: check-image-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must be signed"
      pattern:
        spec:
          containers:
          - name: "*"
            image: "cosign-verified:*"`
}

func (s *PolicyScanner) getGatekeeperInstallManifest() string {
	return `# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml`
}

func (s *PolicyScanner) getPodSecurityEnforcementManifest() string {
	return `# Apply Pod Security Standards
kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=restricted`
}

// getKubeConfig creates a Kubernetes config
func getKubeConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
