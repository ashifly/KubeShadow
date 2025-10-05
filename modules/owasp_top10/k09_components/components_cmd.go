package k09_components

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var ComponentsCmd = &cobra.Command{
	Use:   "k09",
	Short: "K09 - Misconfigured Cluster Components",
	Long: `Detect outdated or misconfigured controllers, webhook misconfigurations, admission webhooks with failurePolicy: Ignore, and CRDs that expose risky code.

This module helps identify cluster component misconfigurations in Kubernetes environments:
- Webhook misconfigurations and security issues
- CRD security risks and exposure
- Outdated controller components
- Admission webhook failures and policies
- Component security hardening

Examples:
  kubeshadow owasp k09 --output json
  kubeshadow owasp k09 --simulate --lab
  kubeshadow owasp k09 --namespace production --severity high`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		output, _ := cmd.Flags().GetString("output")
		namespace, _ := cmd.Flags().GetString("namespace")
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		severity, _ := cmd.Flags().GetString("severity")
		simulate, _ := cmd.Flags().GetBool("simulate")
		lab, _ := cmd.Flags().GetBool("lab")

		// Create scanner
		scanner, err := NewComponentScanner(kubeconfig, namespace, lab)
		if err != nil {
			return fmt.Errorf("failed to create component scanner: %w", err)
		}

		// Run component analysis
		report, err := scanner.RunComponentAnalysis()
		if err != nil {
			return fmt.Errorf("failed to run component analysis: %w", err)
		}

		// Filter by severity if specified
		if severity != "" {
			report = filterBySeverity(report, severity)
		}

		// Run simulation if requested
		if simulate {
			admissionTests, err := scanner.SimulateWebhookAdmission()
			if err != nil {
				return fmt.Errorf("failed to run webhook admission simulation: %w", err)
			}
			report.AdmissionTests = admissionTests

			// Run additional simulations in lab mode
			if lab {
				podAdmissionTests, err := scanner.SimulatePodAdmission()
				if err != nil {
					return fmt.Errorf("failed to run pod admission simulation: %w", err)
				}
				report.AdmissionTests = append(report.AdmissionTests, podAdmissionTests...)

				connectivityTests, err := scanner.TestWebhookConnectivity()
				if err != nil {
					return fmt.Errorf("failed to run webhook connectivity tests: %w", err)
				}
				report.AdmissionTests = append(report.AdmissionTests, connectivityTests...)

				mutationTests, err := scanner.SimulateWebhookMutation()
				if err != nil {
					return fmt.Errorf("failed to run webhook mutation simulation: %w", err)
				}
				report.AdmissionTests = append(report.AdmissionTests, mutationTests...)
			}
		}

		// Analyze webhook risks
		webhookRisks := scanner.AnalyzeWebhookRisks(report.Webhooks)
		report.WebhookRisks = webhookRisks

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

// RunComponentAnalysis runs the complete component analysis
func (cs *ComponentScanner) RunComponentAnalysis() (ComponentReport, error) {
	report := ComponentReport{
		GeneratedAt: time.Now(),
	}

	// Detect webhooks
	webhooks, webhookFindings, err := cs.DetectWebhooks()
	if err != nil {
		return report, fmt.Errorf("failed to detect webhooks: %w", err)
	}
	report.Webhooks = webhooks
	report.Findings = append(report.Findings, webhookFindings...)

	// Detect CRDs
	crds, crdFindings, err := cs.DetectCRDs()
	if err != nil {
		return report, fmt.Errorf("failed to detect CRDs: %w", err)
	}
	report.CRDs = crds
	report.Findings = append(report.Findings, crdFindings...)

	// Detect controllers
	controllers, controllerFindings, err := cs.DetectControllers()
	if err != nil {
		return report, fmt.Errorf("failed to detect controllers: %w", err)
	}
	report.Controllers = controllers
	report.Findings = append(report.Findings, controllerFindings...)

	// Analyze component misconfigurations
	summary, recommendations, err := cs.AnalyzeComponentMisconfigurations()
	if err != nil {
		return report, fmt.Errorf("failed to analyze component misconfigurations: %w", err)
	}
	report.Summary = summary
	report.Recommendations = recommendations

	// Additional security evaluations
	componentSecurityFindings := cs.EvaluateComponentSecurity()
	report.Findings = append(report.Findings, componentSecurityFindings...)

	return report, nil
}

// Helper functions for output formatting
func outputJSON(report ComponentReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputYAML(report ComponentReport) error {
	// Simple YAML output (in a real implementation, use yaml.Marshal)
	fmt.Printf("---\n")
	fmt.Printf("findings: %d\n", len(report.Findings))
	fmt.Printf("summary:\n")
	fmt.Printf("  totalFindings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  criticalCount: %d\n", report.Summary.CriticalCount)
	fmt.Printf("  highCount: %d\n", report.Summary.HighCount)
	fmt.Printf("  mediumCount: %d\n", report.Summary.MediumCount)
	fmt.Printf("  lowCount: %d\n", report.Summary.LowCount)
	fmt.Printf("  componentScore: %.2f\n", report.Summary.ComponentScore)
	fmt.Printf("  webhookCount: %d\n", report.Summary.WebhookCount)
	fmt.Printf("  misconfiguredWebhooks: %d\n", report.Summary.MisconfiguredWebhooks)
	fmt.Printf("  crdCount: %d\n", report.Summary.CRDCount)
	fmt.Printf("  riskyCRDs: %d\n", report.Summary.RiskyCRDs)
	fmt.Printf("  outdatedControllers: %d\n", report.Summary.OutdatedControllers)
	return nil
}

func outputTable(report ComponentReport) error {
	fmt.Printf("🔧 K09 - Misconfigured Cluster Components Analysis\n")
	fmt.Printf("==================================================\n\n")

	// Summary
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Total Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Printf("  Component Score: %.1f%%\n", report.Summary.ComponentScore)
	fmt.Printf("  Webhooks: %d (Misconfigured: %d)\n", report.Summary.WebhookCount, report.Summary.MisconfiguredWebhooks)
	fmt.Printf("  CRDs: %d (Risky: %d)\n", report.Summary.CRDCount, report.Summary.RiskyCRDs)
	fmt.Printf("  Controllers: %d (Outdated: %d)\n", report.Summary.OutdatedControllers, report.Summary.OutdatedControllers)
	fmt.Printf("\n")

	// Webhooks
	if len(report.Webhooks) > 0 {
		fmt.Printf("🔗 Webhooks: %d\n", len(report.Webhooks))
		for _, webhook := range report.Webhooks {
			riskIcon := getRiskIcon(webhook.RiskLevel)
			fmt.Printf("  %s %s (%s) - %s\n", riskIcon, webhook.Name, webhook.Type, webhook.RiskLevel)
			if webhook.CABundle == "" {
				fmt.Printf("    ⚠️ Missing CABundle\n")
			}
			if webhook.FailurePolicy == "Ignore" {
				fmt.Printf("    ⚠️ Failure Policy: Ignore\n")
			}
		}
		fmt.Printf("\n")
	}

	// CRDs
	if len(report.CRDs) > 0 {
		riskyCount := 0
		for _, crd := range report.CRDs {
			if crd.RiskLevel == "high" {
				riskyCount++
			}
		}
		if riskyCount > 0 {
			fmt.Printf("⚠️ Risky CRDs: %d\n", riskyCount)
			for _, crd := range report.CRDs {
				if crd.RiskLevel == "high" {
					fmt.Printf("  %s (%s) - %s\n", crd.Name, crd.Group, crd.RiskLevel)
				}
			}
			fmt.Printf("\n")
		}
	}

	// Controllers
	if len(report.Controllers) > 0 {
		outdatedCount := 0
		for _, controller := range report.Controllers {
			if controller.Outdated {
				outdatedCount++
			}
		}
		if outdatedCount > 0 {
			fmt.Printf("🔄 Outdated Controllers: %d\n", outdatedCount)
			for _, controller := range report.Controllers {
				if controller.Outdated {
					fmt.Printf("  %s (%s) - %s\n", controller.Name, controller.Image, controller.Version)
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

	// Webhook Risks
	if len(report.WebhookRisks) > 0 {
		fmt.Printf("🔍 Webhook Risk Analysis:\n")
		for _, risk := range report.WebhookRisks {
			riskIcon := getRiskIcon(risk.RiskLevel)
			fmt.Printf("  %s %s (Score: %.1f)\n", riskIcon, risk.WebhookName, risk.RiskScore)
			if len(risk.Issues) > 0 {
				fmt.Printf("    Issues: %s\n", strings.Join(risk.Issues, ", "))
			}
			if len(risk.Recommendations) > 0 {
				fmt.Printf("    Recommendations: %s\n", strings.Join(risk.Recommendations, ", "))
			}
		}
		fmt.Printf("\n")
	}

	// Admission Tests
	if len(report.AdmissionTests) > 0 {
		fmt.Printf("🧪 Admission Tests: %d\n", len(report.AdmissionTests))
		successCount := 0
		for _, test := range report.AdmissionTests {
			if test.Success {
				successCount++
			}
		}
		fmt.Printf("  Successful: %d\n", successCount)
		fmt.Printf("  Failed: %d\n", len(report.AdmissionTests)-successCount)
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

func filterBySeverity(report ComponentReport, severity string) ComponentReport {
	var filteredFindings []ComponentFinding
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
	ComponentsCmd.Flags().String("output", "table", "Output format (table, json, yaml)")
	ComponentsCmd.Flags().String("namespace", "", "Kubernetes namespace to scan")
	ComponentsCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file")
	ComponentsCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	ComponentsCmd.Flags().Bool("simulate", false, "Run webhook admission simulation and tests")
	ComponentsCmd.Flags().Bool("lab", false, "Enable lab mode for safe component testing")
}
