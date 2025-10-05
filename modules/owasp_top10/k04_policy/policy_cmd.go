package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
)

// PolicyCmd represents the K04 Policy command
var PolicyCmd = &cobra.Command{
	Use:   "k04",
	Short: "K04 - Lack of Centralized Policy Enforcement",
	Long: `K04 - Lack of Centralized Policy Enforcement

This command detects missing policy enforcement mechanisms and analyzes policy coverage
across the cluster. It identifies gaps in policy enforcement and provides recommendations.

Features:
- Detector: Checks for OPA/Gatekeeper/Kyverno, validates enforcement levels
- Analyzer: Identifies namespaces not covered by policies or with exemptions
- Simulator: Runs policy evaluation engine offline using sample manifests
- Outputs: policy_coverage.json with policy gaps and recommended standard policies

Examples:
  kubeshadow owasp k04
  kubeshadow owasp k04 --namespace kube-system
  kubeshadow owasp k04 --output ./policy-report.json
  kubeshadow owasp k04 --lab --simulate
  kubeshadow owasp k04 --severity critical,high`,
	RunE: runPolicy,
}

var (
	outputPath     string
	namespace      string
	severityFilter string
	labMode        bool
	simulate       bool
	kubeconfig     string
	applyChanges   bool
)

func init() {
	PolicyCmd.Flags().StringVarP(&outputPath, "output", "o", "./policy_coverage.json", "Output file path for policy coverage report")
	PolicyCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Scan specific namespace (default: all namespaces)")
	PolicyCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by severity levels (comma-separated: critical,high,medium,low)")
	PolicyCmd.Flags().BoolVar(&labMode, "lab", false, "Enable lab mode for non-destructive testing")
	PolicyCmd.Flags().BoolVar(&simulate, "simulate", false, "Run simulation to demonstrate policy evaluation (requires --lab)")
	PolicyCmd.Flags().BoolVar(&applyChanges, "apply", false, "Apply changes in lab mode (DANGEROUS - only use in lab)")
	PolicyCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: ~/.kube/config)")
}

func runPolicy(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger.Info("🔒 Starting K04 - Lack of Centralized Policy Enforcement scan...")

	// Create scanner
	scanner, err := NewPolicyScanner(ctx, kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create policy scanner: %v", err)
	}

	// Detect policy enforcement
	logger.Info("📊 Detecting policy enforcement mechanisms...")
	enforcement, err := scanner.DetectPolicyEnforcement(namespace)
	if err != nil {
		return fmt.Errorf("failed to detect policy enforcement: %v", err)
	}

	// Analyze policy gaps
	logger.Info("🔍 Analyzing policy gaps and security issues...")
	findings := scanner.AnalyzePolicyGaps(enforcement)

	// Filter findings if needed
	if severityFilter != "" {
		findings = filterBySeverity(findings, severityFilter)
	}

	// Print summary
	printSummary(findings, enforcement)

	// Run simulation if requested
	if labMode {
		if simulate {
			logger.Info("🧪 Running policy simulation...")
			if err := scanner.RunPolicySimulation(ctx, findings); err != nil {
				logger.Warn("Simulation failed: %v", err)
			}
		}

		if applyChanges {
			logger.Info("⚠️  Applying lab environment changes...")
			if err := scanner.CreatePolicyLabEnvironment(ctx); err != nil {
				logger.Warn("Failed to create lab environment: %v", err)
			}
		}
	}

	// Save results
	if err := saveResults(enforcement, findings, outputPath); err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}

	logger.Info("✅ Policy enforcement scan completed!")
	return nil
}

func printSummary(findings []PolicyFinding, enforcement *PolicyEnforcement) {
	logger.Info("📊 POLICY ENFORCEMENT SCAN SUMMARY")
	logger.Info("==================================================")

	// Policy engines status
	logger.Info("🔧 Policy Engines:")
	if enforcement.Gatekeeper != nil && enforcement.Gatekeeper.Installed {
		logger.Info("   ✅ Gatekeeper: %s (%d constraints)", enforcement.Gatekeeper.Version, len(enforcement.Gatekeeper.Constraints))
	} else {
		logger.Info("   ❌ Gatekeeper: Not installed")
	}

	if enforcement.OPA != nil && enforcement.OPA.Installed {
		logger.Info("   ✅ OPA: %s (%d policies)", enforcement.OPA.Version, len(enforcement.OPA.Policies))
	} else {
		logger.Info("   ❌ OPA: Not installed")
	}

	if enforcement.Kyverno != nil && enforcement.Kyverno.Installed {
		logger.Info("   ✅ Kyverno: %s (%d policies)", enforcement.Kyverno.Version, len(enforcement.Kyverno.Policies))
	} else {
		logger.Info("   ❌ Kyverno: Not installed")
	}

	logger.Info("   📡 Admission Webhooks: %d", len(enforcement.AdmissionWebhooks))
	logger.Info("   📊 Coverage Score: %.2f", enforcement.PolicyCoverage.CoverageScore)
	logger.Info("")

	// Count by severity
	critical := 0
	high := 0
	medium := 0
	low := 0
	totalRisk := 0.0

	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
		totalRisk += finding.RiskScore
	}

	logger.Info("🔍 Policy Gap Analysis:")
	logger.Info("🔴 Critical: %d", critical)
	logger.Info("🟠 High: %d", high)
	logger.Info("🟡 Medium: %d", medium)
	logger.Info("🟢 Low: %d", low)
	logger.Info("📈 Average Risk Score: %.2f", totalRisk/float64(len(findings)))
	logger.Info("")

	// Show top findings
	if len(findings) > 0 {
		logger.Info("🚨 TOP POLICY FINDINGS:")
		logger.Info("")

		// Sort by risk score (simplified - just show first 5)
		maxShow := 5
		if len(findings) < maxShow {
			maxShow = len(findings)
		}

		for i := 0; i < maxShow; i++ {
			finding := findings[i]
			logger.Info("  %d. %s (%s) - Risk: %.2f",
				i+1, finding.PolicyGap, finding.Severity, finding.RiskScore)
			logger.Info("     Resource: %s/%s in %s", finding.ResourceType, finding.ResourceName, finding.Namespace)
			logger.Info("     %s", finding.Description)
		}
	}

	// Show namespace coverage
	if len(enforcement.PolicyCoverage.Namespaces) > 0 {
		logger.Info("")
		logger.Info("📋 NAMESPACE COVERAGE:")
		for _, ns := range enforcement.PolicyCoverage.Namespaces {
			var riskIcon string
			switch ns.RiskLevel {
			case "CRITICAL":
				riskIcon = "🔴"
			case "HIGH":
				riskIcon = "🟠"
			case "MEDIUM":
				riskIcon = "🟡"
			default:
				riskIcon = "🟢"
			}

			logger.Info("   %s %s: %.2f (%s)", riskIcon, ns.Name, ns.CoverageScore, ns.RiskLevel)
			if len(ns.MissingPolicies) > 0 {
				logger.Info("      Missing: %s", strings.Join(ns.MissingPolicies, ", "))
			}
		}
	}

	// Show recommendations
	if len(enforcement.PolicyCoverage.Recommendations) > 0 {
		logger.Info("")
		logger.Info("💡 RECOMMENDATIONS:")
		for i, rec := range enforcement.PolicyCoverage.Recommendations {
			if i >= 3 { // Show top 3
				break
			}
			logger.Info("  %d. %s (%s)", i+1, rec.Description, rec.Priority)
		}
	}
}

func filterBySeverity(findings []PolicyFinding, severityFilter string) []PolicyFinding {
	severities := make(map[string]bool)
	for _, s := range []string{"critical", "high", "medium", "low"} {
		severities[s] = false
	}

	// Parse severity filter
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if contains(severityFilter, s) {
			severities[s] = true
		}
	}

	var filtered []PolicyFinding
	for _, finding := range findings {
		if severities[strings.ToLower(finding.Severity)] {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func saveResults(enforcement *PolicyEnforcement, findings []PolicyFinding, outputPath string) error {
	result := map[string]interface{}{
		"enforcement": enforcement,
		"findings":    findings,
		"summary": map[string]interface{}{
			"totalFindings": len(findings),
			"coverageScore": enforcement.PolicyCoverage.CoverageScore,
			"policyEngines": map[string]bool{
				"gatekeeper": enforcement.Gatekeeper != nil && enforcement.Gatekeeper.Installed,
				"opa":        enforcement.OPA != nil && enforcement.OPA.Installed,
				"kyverno":    enforcement.Kyverno != nil && enforcement.Kyverno.Installed,
			},
		},
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write results to file: %w", err)
	}

	logger.Info("💾 Results saved to %s", outputPath)
	return nil
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
