package k10_vulnerabilities

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var VulnerabilitiesCmd = &cobra.Command{
	Use:   "k10",
	Short: "K10 - Outdated and Vulnerable Kubernetes Components",
	Long: `Detect outdated versions of kubelet, API server, ingress, CNI, CSI drivers, container runtime, and known CVEs affecting current versions.

This module helps identify vulnerability issues in Kubernetes environments:
- Outdated Kubernetes components and versions
- Known CVEs affecting current versions
- Container runtime vulnerabilities
- CNI and CSI driver vulnerabilities
- Ingress controller vulnerabilities
- Upgrade planning and preflight testing

Examples:
  kubeshadow owasp k10 --output json
  kubeshadow owasp k10 --simulate --lab
  kubeshadow owasp k10 --namespace production --severity critical`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		output, _ := cmd.Flags().GetString("output")
		namespace, _ := cmd.Flags().GetString("namespace")
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		severity, _ := cmd.Flags().GetString("severity")
		simulate, _ := cmd.Flags().GetBool("simulate")
		lab, _ := cmd.Flags().GetBool("lab")

		// Create scanner
		scanner, err := NewVulnerabilityScanner(kubeconfig, namespace, lab)
		if err != nil {
			return fmt.Errorf("failed to create vulnerability scanner: %w", err)
		}

		// Run vulnerability analysis
		report, err := scanner.RunVulnerabilityAnalysis()
		if err != nil {
			return fmt.Errorf("failed to run vulnerability analysis: %w", err)
		}

		// Filter by severity if specified
		if severity != "" {
			report = filterBySeverity(report, severity)
		}

		// Run simulation if requested
		if simulate {
			upgradePlans, err := scanner.SimulateUpgradePlans()
			if err != nil {
				return fmt.Errorf("failed to run upgrade plan simulation: %w", err)
			}
			report.UpgradePlans = upgradePlans

			// Run additional simulations in lab mode
			if lab {
				preflightTests, err := scanner.SimulatePreflightTests()
				if err != nil {
					return fmt.Errorf("failed to run preflight tests: %w", err)
				}
				report.PreflightTests = preflightTests

				vulnerabilityScanning, err := scanner.SimulateVulnerabilityScanning()
				if err != nil {
					return fmt.Errorf("failed to run vulnerability scanning: %w", err)
				}
				report.Findings = append(report.Findings, vulnerabilityScanning...)

				patchManagement, err := scanner.SimulatePatchManagement()
				if err != nil {
					return fmt.Errorf("failed to run patch management simulation: %w", err)
				}
				report.Findings = append(report.Findings, patchManagement...)
			}
		}

		// Prioritize vulnerabilities
		report.Findings = scanner.PrioritizeVulnerabilities(report.Findings)

		// Output results
		switch output {
		case "json":
			return outputJSON(report)
		case "yaml":
			return outputYAML(report)
		default:
			return outputTable(report)
		}
	},
}

// RunVulnerabilityAnalysis runs the complete vulnerability analysis
func (vs *VulnerabilityScanner) RunVulnerabilityAnalysis() (VulnerabilityReport, error) {
	report := VulnerabilityReport{
		GeneratedAt: time.Now(),
	}

	// Detect Kubernetes version
	kubernetesVersion, versionFindings, err := vs.DetectKubernetesVersion()
	if err != nil {
		return report, fmt.Errorf("failed to detect Kubernetes version: %w", err)
	}
	report.KubernetesVersion = kubernetesVersion
	report.Findings = append(report.Findings, versionFindings...)

	// Detect node vulnerabilities
	nodes, nodeFindings, err := vs.DetectNodeVulnerabilities()
	if err != nil {
		return report, fmt.Errorf("failed to detect node vulnerabilities: %w", err)
	}
	report.Nodes = nodes
	report.Findings = append(report.Findings, nodeFindings...)

	// Detect component vulnerabilities
	components, componentFindings, err := vs.DetectComponentVulnerabilities()
	if err != nil {
		return report, fmt.Errorf("failed to detect component vulnerabilities: %w", err)
	}
	report.Components = components
	report.Findings = append(report.Findings, componentFindings...)

	// Detect addon vulnerabilities
	addons, addonFindings, err := vs.DetectAddonVulnerabilities()
	if err != nil {
		return report, fmt.Errorf("failed to detect addon vulnerabilities: %w", err)
	}
	report.Addons = addons
	report.Findings = append(report.Findings, addonFindings...)

	// Analyze vulnerabilities
	summary, recommendations, err := vs.AnalyzeVulnerabilities()
	if err != nil {
		return report, fmt.Errorf("failed to analyze vulnerabilities: %w", err)
	}
	report.Summary = summary
	report.Recommendations = recommendations

	// Additional security evaluations
	vulnerabilityImpactFindings := vs.EvaluateVulnerabilityImpact()
	report.Findings = append(report.Findings, vulnerabilityImpactFindings...)

	return report, nil
}

// Helper functions for output formatting
func outputJSON(report VulnerabilityReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputYAML(report VulnerabilityReport) error {
	// Simple YAML output (in a real implementation, use yaml.Marshal)
	fmt.Printf("---\n")
	fmt.Printf("findings: %d\n", len(report.Findings))
	fmt.Printf("summary:\n")
	fmt.Printf("  totalFindings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  criticalCount: %d\n", report.Summary.CriticalCount)
	fmt.Printf("  highCount: %d\n", report.Summary.HighCount)
	fmt.Printf("  mediumCount: %d\n", report.Summary.MediumCount)
	fmt.Printf("  lowCount: %d\n", report.Summary.LowCount)
	fmt.Printf("  vulnerabilityScore: %.2f\n", report.Summary.VulnerabilityScore)
	fmt.Printf("  cveCount: %d\n", report.Summary.CVECount)
	fmt.Printf("  criticalCVEs: %d\n", report.Summary.CriticalCVEs)
	fmt.Printf("  highCVEs: %d\n", report.Summary.HighCVEs)
	fmt.Printf("  outdatedComponents: %d\n", report.Summary.OutdatedComponents)
	fmt.Printf("  kubernetesVersion: %s\n", report.Summary.KubernetesVersion)
	return nil
}

func outputTable(report VulnerabilityReport) error {
	fmt.Printf("🔍 K10 - Outdated and Vulnerable Kubernetes Components Analysis\n")
	fmt.Printf("===============================================================\n\n")

	// Summary
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Total Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Printf("  Vulnerability Score: %.1f%%\n", report.Summary.VulnerabilityScore)
	fmt.Printf("  CVEs: %d (Critical: %d, High: %d)\n", report.Summary.CVECount, report.Summary.CriticalCVEs, report.Summary.HighCVEs)
	fmt.Printf("  Outdated Components: %d\n", report.Summary.OutdatedComponents)
	fmt.Printf("  Kubernetes Version: %s\n", report.Summary.KubernetesVersion)
	fmt.Printf("\n")

	// Kubernetes Version
	if report.KubernetesVersion.GitVersion != "" {
		fmt.Printf("🔧 Kubernetes Version: %s\n", report.KubernetesVersion.GitVersion)
		fmt.Printf("  Major: %s, Minor: %s\n", report.KubernetesVersion.Major, report.KubernetesVersion.Minor)
		fmt.Printf("  Build Date: %s\n", report.KubernetesVersion.BuildDate)
		fmt.Printf("\n")
	}

	// Components
	if len(report.Components) > 0 {
		fmt.Printf("🔧 Components: %d\n", len(report.Components))
		for _, component := range report.Components {
			riskIcon := getRiskIcon(component.RiskLevel)
			fmt.Printf("  %s %s (%s) - %s\n", riskIcon, component.Name, component.Version, component.RiskLevel)
			if component.Outdated {
				fmt.Printf("    ⚠️ Outdated (Latest: %s)\n", component.LatestVersion)
			}
			if component.Vulnerable {
				fmt.Printf("    🔴 Vulnerable (%d CVEs)\n", len(component.CVEs))
			}
		}
		fmt.Printf("\n")
	}

	// Nodes
	if len(report.Nodes) > 0 {
		vulnerableNodes := 0
		for _, node := range report.Nodes {
			if node.Vulnerable {
				vulnerableNodes++
			}
		}
		if vulnerableNodes > 0 {
			fmt.Printf("🖥️ Vulnerable Nodes: %d\n", vulnerableNodes)
			for _, node := range report.Nodes {
				if node.Vulnerable {
					fmt.Printf("  %s (%s) - %s\n", node.Name, node.KubeletVersion, node.Runtime)
					if len(node.CVEs) > 0 {
						fmt.Printf("    CVEs: %d\n", len(node.CVEs))
					}
				}
			}
			fmt.Printf("\n")
		}
	}

	// Addons
	if len(report.Addons) > 0 {
		outdatedAddons := 0
		for _, addon := range report.Addons {
			if addon.Outdated {
				outdatedAddons++
			}
		}
		if outdatedAddons > 0 {
			fmt.Printf("🔌 Outdated Addons: %d\n", outdatedAddons)
			for _, addon := range report.Addons {
				if addon.Outdated {
					fmt.Printf("  %s (%s) - %s (Latest: %s)\n", addon.Name, addon.Type, addon.Version, addon.LatestVersion)
				}
			}
			fmt.Printf("\n")
		}
	}

	// Findings
	if len(report.Findings) > 0 {
		fmt.Printf("🚨 Findings:\n")
		for _, finding := range report.Findings {
			severityIcon := getSeverityIcon(finding.Severity)
			fmt.Printf("  %s %s: %s\n", severityIcon, finding.Severity, finding.Title)
			fmt.Printf("    Description: %s\n", finding.Description)
			fmt.Printf("    Resource: %s/%s\n", finding.Namespace, finding.Resource)
			fmt.Printf("    Risk Score: %.1f\n", finding.RiskScore)
			fmt.Printf("    Remediation: %s\n\n", finding.Remediation)
		}
	}

	// Upgrade Plans
	if len(report.UpgradePlans) > 0 {
		fmt.Printf("📋 Upgrade Plans: %d\n", len(report.UpgradePlans))
		for _, plan := range report.UpgradePlans {
			fmt.Printf("  %s: %s → %s (%s)\n", plan.Component, plan.CurrentVersion, plan.TargetVersion, plan.RiskLevel)
			fmt.Printf("    Steps: %d\n", len(plan.Steps))
			fmt.Printf("    Pre-checks: %d\n", len(plan.PreChecks))
		}
		fmt.Printf("\n")
	}

	// Preflight Tests
	if len(report.PreflightTests) > 0 {
		fmt.Printf("🧪 Preflight Tests: %d\n", len(report.PreflightTests))
		requiredCount := 0
		for _, test := range report.PreflightTests {
			if test.Required {
				requiredCount++
			}
		}
		fmt.Printf("  Required: %d\n", requiredCount)
		fmt.Printf("  Optional: %d\n", len(report.PreflightTests)-requiredCount)
		fmt.Printf("\n")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		fmt.Printf("💡 Recommendations:\n")
		for i, rec := range report.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
		fmt.Printf("\n")
	}

	return nil
}

func filterBySeverity(report VulnerabilityReport, severity string) VulnerabilityReport {
	var filteredFindings []VulnerabilityFinding
	for _, finding := range report.Findings {
		if strings.EqualFold(finding.Severity, severity) {
			filteredFindings = append(filteredFindings, finding)
		}
	}
	report.Findings = filteredFindings
	return report
}

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func getRiskIcon(riskLevel string) string {
	switch strings.ToLower(riskLevel) {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func init() {
	VulnerabilitiesCmd.Flags().String("output", "table", "Output format (table, json, yaml)")
	VulnerabilitiesCmd.Flags().String("namespace", "", "Kubernetes namespace to scan")
	VulnerabilitiesCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file")
	VulnerabilitiesCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	VulnerabilitiesCmd.Flags().Bool("simulate", false, "Run vulnerability scanning simulation and upgrade planning")
	VulnerabilitiesCmd.Flags().Bool("lab", false, "Enable lab mode for safe vulnerability testing")
}
