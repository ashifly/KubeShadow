package policy

import (
	"fmt"
	"math"
	"strings"

	"kubeshadow/pkg/logger"
)

// AnalyzePolicyGaps analyzes policy enforcement for security gaps
func (s *PolicyScanner) AnalyzePolicyGaps(enforcement *PolicyEnforcement) []PolicyFinding {
	logger.Info("🔍 Analyzing policy gaps and security issues...")

	findings := []PolicyFinding{}

	// Analyze missing policy engines
	if enforcement.Gatekeeper == nil || !enforcement.Gatekeeper.Installed {
		if enforcement.OPA == nil || !enforcement.OPA.Installed {
			if enforcement.Kyverno == nil || !enforcement.Kyverno.Installed {
				findings = append(findings, PolicyFinding{
					Namespace:      "cluster-wide",
					ResourceType:   "PolicyEngine",
					ResourceName:   "none",
					PolicyGap:      "No policy engine installed",
					Severity:       "CRITICAL",
					RiskScore:      1.0,
					Description:    "No centralized policy enforcement mechanism detected",
					Recommendation: "Install Gatekeeper, OPA, or Kyverno for policy enforcement",
					StandardPolicy: "gatekeeper-installation",
				})
			}
		}
	}

	// Analyze namespace coverage gaps
	for _, nsCoverage := range enforcement.PolicyCoverage.Namespaces {
		if nsCoverage.CoverageScore < 0.5 {
			finding := PolicyFinding{
				Namespace:      nsCoverage.Name,
				ResourceType:   "Namespace",
				ResourceName:   nsCoverage.Name,
				PolicyGap:      "Insufficient policy coverage",
				Severity:       s.getSeverityFromScore(nsCoverage.CoverageScore),
				RiskScore:      1.0 - nsCoverage.CoverageScore,
				Description:    fmt.Sprintf("Namespace has low policy coverage (%.2f)", nsCoverage.CoverageScore),
				Recommendation: "Apply standard policies to improve coverage",
				StandardPolicy: "namespace-policy-coverage",
			}

			// Add specific missing policies
			if len(nsCoverage.MissingPolicies) > 0 {
				finding.Description += fmt.Sprintf(". Missing policies: %s", strings.Join(nsCoverage.MissingPolicies, ", "))
			}

			findings = append(findings, finding)
		}

		// Check for exemptions
		if len(nsCoverage.Exemptions) > 0 {
			findings = append(findings, PolicyFinding{
				Namespace:      nsCoverage.Name,
				ResourceType:   "Namespace",
				ResourceName:   nsCoverage.Name,
				PolicyGap:      "Policy exemptions detected",
				Severity:       "HIGH",
				RiskScore:      0.8,
				Description:    fmt.Sprintf("Namespace has policy exemptions: %s", strings.Join(nsCoverage.Exemptions, ", ")),
				Recommendation: "Review and minimize policy exemptions",
				StandardPolicy: "exemption-review",
			})
		}
	}

	// Analyze resource type coverage gaps
	for _, resourceCoverage := range enforcement.PolicyCoverage.ResourceTypes {
		if resourceCoverage.CoverageScore < 0.6 {
			findings = append(findings, PolicyFinding{
				Namespace:      "cluster-wide",
				ResourceType:   resourceCoverage.ResourceType,
				ResourceName:   resourceCoverage.ResourceType,
				PolicyGap:      "Insufficient resource policy coverage",
				Severity:       s.getSeverityFromScore(resourceCoverage.CoverageScore),
				RiskScore:      1.0 - resourceCoverage.CoverageScore,
				Description:    fmt.Sprintf("Resource type %s has low policy coverage (%.2f)", resourceCoverage.ResourceType, resourceCoverage.CoverageScore),
				Recommendation: "Apply specific policies for this resource type",
				StandardPolicy: fmt.Sprintf("%s-policy", resourceCoverage.ResourceType),
			})
		}
	}

	// Analyze admission webhook gaps
	if len(enforcement.AdmissionWebhooks) == 0 {
		findings = append(findings, PolicyFinding{
			Namespace:      "cluster-wide",
			ResourceType:   "AdmissionWebhook",
			ResourceName:   "none",
			PolicyGap:      "No admission webhooks configured",
			Severity:       "MEDIUM",
			RiskScore:      0.6,
			Description:    "No admission webhooks detected for policy enforcement",
			Recommendation: "Configure admission webhooks for policy enforcement",
			StandardPolicy: "admission-webhook-setup",
		})
	}

	// Analyze policy engine specific issues
	if enforcement.Gatekeeper != nil && enforcement.Gatekeeper.Installed {
		s.analyzeGatekeeperIssues(enforcement.Gatekeeper, &findings)
	}

	if enforcement.OPA != nil && enforcement.OPA.Installed {
		s.analyzeOPAIssues(enforcement.OPA, &findings)
	}

	if enforcement.Kyverno != nil && enforcement.Kyverno.Installed {
		s.analyzeKyvernoIssues(enforcement.Kyverno, &findings)
	}

	logger.Info("📊 Found %d policy gap findings", len(findings))
	return findings
}

// analyzeGatekeeperIssues analyzes Gatekeeper-specific issues
func (s *PolicyScanner) analyzeGatekeeperIssues(gatekeeper *GatekeeperInfo, findings *[]PolicyFinding) {
	// Check for constraints in warn mode
	for _, constraint := range gatekeeper.Constraints {
		if constraint.Enforcement == "warn" {
			*findings = append(*findings, PolicyFinding{
				Namespace:      constraint.Namespace,
				ResourceType:   "Constraint",
				ResourceName:   constraint.Name,
				PolicyGap:      "Constraint in warn mode",
				Severity:       "MEDIUM",
				RiskScore:      0.5,
				Description:    fmt.Sprintf("Constraint %s is in warn mode, not enforcing", constraint.Name),
				Recommendation: "Change constraint enforcement to 'deny' mode",
				StandardPolicy: "constraint-enforcement",
			})
		}

		// Check for violations
		if constraint.Violations > 0 {
			*findings = append(*findings, PolicyFinding{
				Namespace:      constraint.Namespace,
				ResourceType:   "Constraint",
				ResourceName:   constraint.Name,
				PolicyGap:      "Constraint violations detected",
				Severity:       "HIGH",
				RiskScore:      math.Min(1.0, float64(constraint.Violations)/10.0),
				Description:    fmt.Sprintf("Constraint %s has %d violations", constraint.Name, constraint.Violations),
				Recommendation: "Review and fix constraint violations",
				StandardPolicy: "constraint-violation-review",
			})
		}
	}

	// Check for missing standard constraints
	standardConstraints := []string{"K8sRequiredLabels", "K8sRequiredAnnotations", "K8sContainerLimits"}
	existingConstraints := make(map[string]bool)
	for _, constraint := range gatekeeper.Constraints {
		existingConstraints[constraint.Kind] = true
	}

	for _, standard := range standardConstraints {
		if !existingConstraints[standard] {
			*findings = append(*findings, PolicyFinding{
				Namespace:      "cluster-wide",
				ResourceType:   "ConstraintTemplate",
				ResourceName:   standard,
				PolicyGap:      "Missing standard constraint",
				Severity:       "MEDIUM",
				RiskScore:      0.4,
				Description:    fmt.Sprintf("Standard constraint %s is not deployed", standard),
				Recommendation: "Deploy standard constraint templates",
				StandardPolicy: fmt.Sprintf("%s-constraint", strings.ToLower(standard)),
			})
		}
	}
}

// analyzeOPAIssues analyzes OPA-specific issues
func (s *PolicyScanner) analyzeOPAIssues(opa *OPAInfo, findings *[]PolicyFinding) {
	// Check for disabled policies
	for _, policy := range opa.Policies {
		if !policy.Enabled {
			*findings = append(*findings, PolicyFinding{
				Namespace:      policy.Namespace,
				ResourceType:   "OPAPolicy",
				ResourceName:   policy.Name,
				PolicyGap:      "Disabled OPA policy",
				Severity:       "MEDIUM",
				RiskScore:      0.5,
				Description:    fmt.Sprintf("OPA policy %s is disabled", policy.Name),
				Recommendation: "Enable the policy or remove if not needed",
				StandardPolicy: "opa-policy-enablement",
			})
		}
	}

	// Check for missing standard OPA policies
	standardPolicies := []string{"pod-security", "no-privileged", "resource-limits"}
	existingPolicies := make(map[string]bool)
	for _, policy := range opa.Policies {
		existingPolicies[policy.Name] = true
	}

	for _, standard := range standardPolicies {
		if !existingPolicies[standard] {
			*findings = append(*findings, PolicyFinding{
				Namespace:      "cluster-wide",
				ResourceType:   "OPAPolicy",
				ResourceName:   standard,
				PolicyGap:      "Missing standard OPA policy",
				Severity:       "MEDIUM",
				RiskScore:      0.4,
				Description:    fmt.Sprintf("Standard OPA policy %s is not deployed", standard),
				Recommendation: "Deploy standard OPA policies",
				StandardPolicy: fmt.Sprintf("%s-opa-policy", standard),
			})
		}
	}
}

// analyzeKyvernoIssues analyzes Kyverno-specific issues
func (s *PolicyScanner) analyzeKyvernoIssues(kyverno *KyvernoInfo, findings *[]PolicyFinding) {
	// Check for policies in audit mode
	for _, policy := range kyverno.Policies {
		if policy.Validation == "audit" {
			*findings = append(*findings, PolicyFinding{
				Namespace:      policy.Namespace,
				ResourceType:   "KyvernoPolicy",
				ResourceName:   policy.Name,
				PolicyGap:      "Policy in audit mode",
				Severity:       "MEDIUM",
				RiskScore:      0.5,
				Description:    fmt.Sprintf("Kyverno policy %s is in audit mode, not enforcing", policy.Name),
				Recommendation: "Change policy validation to 'enforce' mode",
				StandardPolicy: "kyverno-policy-enforcement",
			})
		}
	}

	// Check for missing background validation
	for _, policy := range kyverno.Policies {
		if !policy.Background {
			*findings = append(*findings, PolicyFinding{
				Namespace:      policy.Namespace,
				ResourceType:   "KyvernoPolicy",
				ResourceName:   policy.Name,
				PolicyGap:      "Policy without background validation",
				Severity:       "LOW",
				RiskScore:      0.3,
				Description:    fmt.Sprintf("Kyverno policy %s does not have background validation enabled", policy.Name),
				Recommendation: "Enable background validation for existing resources",
				StandardPolicy: "kyverno-background-validation",
			})
		}
	}
}

// getSeverityFromScore converts a coverage score to severity level
func (s *PolicyScanner) getSeverityFromScore(score float64) string {
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

// GeneratePolicyRecommendations generates specific policy recommendations
func (s *PolicyScanner) GeneratePolicyRecommendations(findings []PolicyFinding) []Recommendation {
	recommendations := []Recommendation{}

	// Group findings by type
	policyEngineMissing := false
	namespaceGaps := make(map[string]bool)
	resourceGaps := make(map[string]bool)

	for _, finding := range findings {
		switch finding.PolicyGap {
		case "No policy engine installed":
			policyEngineMissing = true
		case "Insufficient policy coverage":
			namespaceGaps[finding.Namespace] = true
		case "Insufficient resource policy coverage":
			resourceGaps[finding.ResourceType] = true
		}
	}

	// Generate recommendations based on findings
	if policyEngineMissing {
		recommendations = append(recommendations, Recommendation{
			Type:           "Install Policy Engine",
			Description:    "Install a policy engine for centralized policy enforcement",
			Priority:       "CRITICAL",
			Implementation: "Install Gatekeeper, OPA, or Kyverno",
			Manifest:       s.getPolicyEngineInstallManifest(),
		})
	}

	if len(namespaceGaps) > 0 {
		recommendations = append(recommendations, Recommendation{
			Type:           "Apply Namespace Policies",
			Description:    fmt.Sprintf("Apply policies to %d namespaces with insufficient coverage", len(namespaceGaps)),
			Priority:       "HIGH",
			Implementation: "Apply standard policies to namespaces",
			Manifest:       s.getNamespacePolicyManifest(),
		})
	}

	if len(resourceGaps) > 0 {
		recommendations = append(recommendations, Recommendation{
			Type:           "Apply Resource Policies",
			Description:    fmt.Sprintf("Apply policies for %d resource types with insufficient coverage", len(resourceGaps)),
			Priority:       "MEDIUM",
			Implementation: "Apply resource-specific policies",
			Manifest:       s.getResourcePolicyManifest(),
		})
	}

	return recommendations
}

// Helper methods for generating manifests
func (s *PolicyScanner) getPolicyEngineInstallManifest() string {
	return `# Install Gatekeeper for policy enforcement
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Wait for Gatekeeper to be ready
kubectl wait --for=condition=Ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=300s`
}

func (s *PolicyScanner) getNamespacePolicyManifest() string {
	return `# Apply Pod Security Standards to namespaces
kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=restricted
kubectl label namespace <namespace> pod-security.kubernetes.io/audit=restricted
kubectl label namespace <namespace> pod-security.kubernetes.io/warn=restricted`
}

func (s *PolicyScanner) getResourcePolicyManifest() string {
	return `# Apply resource-specific policies
# Example: Network policies for services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <namespace>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`
}
