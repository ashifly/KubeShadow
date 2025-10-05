package k06_auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var AuthCmd = &cobra.Command{
	Use:   "k06",
	Short: "K06 - Broken Authentication Mechanisms",
	Long: `Detect weak API server authentication, anonymous access, kubeconfig/token exposure, and public dashboards.

This module helps identify authentication vulnerabilities in Kubernetes environments:
- API server authentication configuration
- Anonymous access detection
- Kubeconfig and token exposure
- Public endpoint security
- Service account token security
- RBAC effectiveness

Examples:
  kubeshadow owasp k06 --output json
  kubeshadow owasp k06 --simulate --lab
  kubeshadow owasp k06 --namespace production --severity critical`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		output, _ := cmd.Flags().GetString("output")
		namespace, _ := cmd.Flags().GetString("namespace")
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		severity, _ := cmd.Flags().GetString("severity")
		simulate, _ := cmd.Flags().GetBool("simulate")
		lab, _ := cmd.Flags().GetBool("lab")

		// Create scanner
		scanner, err := NewAuthScanner(kubeconfig, namespace, lab)
		if err != nil {
			return fmt.Errorf("failed to create auth scanner: %w", err)
		}

		// Run authentication analysis
		report, err := scanner.RunAuthAnalysis()
		if err != nil {
			return fmt.Errorf("failed to run auth analysis: %w", err)
		}

		// Filter by severity if specified
		if severity != "" {
			report = filterBySeverity(report, severity)
		}

		// Run simulation if requested
		if simulate {
			authTests, err := scanner.SimulateAuthTests()
			if err != nil {
				return fmt.Errorf("failed to run auth tests: %w", err)
			}
			report.AuthTests = authTests

			// Run credential theft simulation in lab mode
			if lab {
				theftTests, err := scanner.SimulateCredentialTheft()
				if err != nil {
					return fmt.Errorf("failed to run credential theft simulation: %w", err)
				}
				report.AuthTests = append(report.AuthTests, theftTests...)
			}
		}

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

// RunAuthAnalysis runs the complete authentication analysis
func (as *AuthScanner) RunAuthAnalysis() (AuthReport, error) {
	report := AuthReport{
		GeneratedAt: time.Now(),
	}

	// Detect API server authentication
	apiConfig, apiFindings, err := as.DetectAPIServerAuth()
	if err != nil {
		return report, fmt.Errorf("failed to detect API server auth: %w", err)
	}
	report.APIServerConfig = apiConfig
	report.Findings = append(report.Findings, apiFindings...)

	// Detect kubeconfig exposure
	kubeConfigs, kubeFindings, err := as.DetectKubeConfigs()
	if err != nil {
		return report, fmt.Errorf("failed to detect kubeconfigs: %w", err)
	}
	report.KubeConfigs = kubeConfigs
	report.Findings = append(report.Findings, kubeFindings...)

	// Detect token exposure
	tokens, tokenFindings, err := as.DetectTokens()
	if err != nil {
		return report, fmt.Errorf("failed to detect tokens: %w", err)
	}
	report.Tokens = tokens
	report.Findings = append(report.Findings, tokenFindings...)

	// Detect public endpoints
	endpoints, endpointFindings, err := as.DetectPublicEndpoints()
	if err != nil {
		return report, fmt.Errorf("failed to detect public endpoints: %w", err)
	}
	report.PublicEndpoints = endpoints
	report.Findings = append(report.Findings, endpointFindings...)

	// Analyze authentication coverage
	summary, recommendations, err := as.AnalyzeAuthCoverage()
	if err != nil {
		return report, fmt.Errorf("failed to analyze auth coverage: %w", err)
	}
	report.Summary = summary
	report.Recommendations = recommendations

	// Additional security evaluations
	tokenSecurityFindings := as.EvaluateTokenSecurity(tokens)
	report.Findings = append(report.Findings, tokenSecurityFindings...)

	kubeconfigSecurityFindings := as.EvaluateKubeConfigSecurity(kubeConfigs)
	report.Findings = append(report.Findings, kubeconfigSecurityFindings...)

	return report, nil
}

// Helper functions for output formatting
func outputJSON(report AuthReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputYAML(report AuthReport) error {
	// Simple YAML output (in a real implementation, use yaml.Marshal)
	fmt.Printf("---\n")
	fmt.Printf("findings: %d\n", len(report.Findings))
	fmt.Printf("summary:\n")
	fmt.Printf("  totalFindings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  criticalCount: %d\n", report.Summary.CriticalCount)
	fmt.Printf("  highCount: %d\n", report.Summary.HighCount)
	fmt.Printf("  mediumCount: %d\n", report.Summary.MediumCount)
	fmt.Printf("  lowCount: %d\n", report.Summary.LowCount)
	fmt.Printf("  authScore: %.2f\n", report.Summary.AuthScore)
	fmt.Printf("  anonymousAccess: %t\n", report.Summary.AnonymousAccess)
	fmt.Printf("  exposedCredentials: %d\n", report.Summary.ExposedCredentials)
	fmt.Printf("  publicEndpoints: %d\n", report.Summary.PublicEndpoints)
	return nil
}

func outputTable(report AuthReport) error {
	fmt.Printf("🔐 K06 - Broken Authentication Mechanisms Analysis\n")
	fmt.Printf("==================================================\n\n")

	// Summary
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Total Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Printf("  Auth Score: %.1f%%\n", report.Summary.AuthScore)
	fmt.Printf("  Anonymous Access: %t\n", report.Summary.AnonymousAccess)
	fmt.Printf("  Exposed Credentials: %d\n", report.Summary.ExposedCredentials)
	fmt.Printf("  Public Endpoints: %d\n", report.Summary.PublicEndpoints)
	fmt.Printf("  Token Age (days): %d\n", report.Summary.TokenAge)
	fmt.Printf("  Credential Rotation: %t\n\n", report.Summary.CredentialRotation)

	// API Server Configuration
	fmt.Printf("🔧 API Server Configuration:\n")
	fmt.Printf("  Anonymous Auth: %t\n", report.APIServerConfig.AnonymousAuth)
	fmt.Printf("  RBAC Enabled: %t\n", report.APIServerConfig.RBACEnabled)
	fmt.Printf("  Audit Logging: %t\n", report.APIServerConfig.AuditLogging)
	fmt.Printf("  Admission Plugins: %d\n", len(report.APIServerConfig.AdmissionPlugins))
	fmt.Printf("\n")

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

	// Auth Tests
	if len(report.AuthTests) > 0 {
		fmt.Printf("🧪 Authentication Tests:\n")
		for _, test := range report.AuthTests {
			statusIcon := "✅"
			if !test.Success {
				statusIcon = "❌"
			}
			fmt.Printf("  %s %s\n", statusIcon, test.TestName)
			fmt.Printf("    Description: %s\n", test.Description)
			fmt.Printf("    Risk Level: %s\n", test.RiskLevel)
			fmt.Printf("    Details: %s\n\n", test.Details)
		}
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

func filterBySeverity(report AuthReport, severity string) AuthReport {
	var filteredFindings []AuthFinding
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

func init() {
	AuthCmd.Flags().String("output", "table", "Output format (table, json, yaml)")
	AuthCmd.Flags().String("namespace", "", "Kubernetes namespace to scan")
	AuthCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file")
	AuthCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	AuthCmd.Flags().Bool("simulate", false, "Run authentication tests and simulations")
	AuthCmd.Flags().Bool("lab", false, "Enable lab mode for safe testing")
}
