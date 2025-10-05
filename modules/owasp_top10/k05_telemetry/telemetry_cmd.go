package k05_telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var TelemetryCmd = &cobra.Command{
	Use:   "k05",
	Short: "K05 - Inadequate Logging and Monitoring",
	Long: `Detect missing audit logs, eBPF probes, weak retention, and lack of SIEM integration.

This module helps identify gaps in Kubernetes telemetry and logging infrastructure:
- Kubernetes audit logging configuration
- eBPF-based security monitoring (Falco, Tetragon)
- SIEM integration and log forwarding
- Log retention and rotation policies
- Detection pipeline effectiveness

Examples:
  kubeshadow owasp k05 --output json
  kubeshadow owasp k05 --simulate --lab
  kubeshadow owasp k05 --namespace production --severity high`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		output, _ := cmd.Flags().GetString("output")
		namespace, _ := cmd.Flags().GetString("namespace")
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		severity, _ := cmd.Flags().GetString("severity")
		simulate, _ := cmd.Flags().GetBool("simulate")
		lab, _ := cmd.Flags().GetBool("lab")

		// Create scanner
		scanner, err := NewTelemetryScanner(kubeconfig, namespace)
		if err != nil {
			return fmt.Errorf("failed to create telemetry scanner: %w", err)
		}

		// Run telemetry analysis
		report, err := scanner.RunTelemetryAnalysis()
		if err != nil {
			return fmt.Errorf("failed to run telemetry analysis: %w", err)
		}

		// Filter by severity if specified
		if severity != "" {
			report = filterBySeverity(report, severity)
		}

		// Run simulation if requested
		if simulate {
			pipelineTest, err := scanner.TestDetectionPipeline()
			if err != nil {
				return fmt.Errorf("failed to run detection pipeline test: %w", err)
			}
			report.DetectionTest = &pipelineTest
		}

		// Generate lab resources if requested
		if lab {
			if err := scanner.GenerateLabResources(); err != nil {
				return fmt.Errorf("failed to generate lab resources: %w", err)
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

// RunTelemetryAnalysis runs the complete telemetry analysis
func (ts *TelemetryScanner) RunTelemetryAnalysis() (TelemetryReport, error) {
	report := TelemetryReport{
		GeneratedAt: time.Now(),
	}

	// Detect audit logging
	auditPolicy, auditFindings, err := ts.DetectAuditLogging()
	if err != nil {
		return report, fmt.Errorf("failed to detect audit logging: %w", err)
	}
	report.AuditPolicy = auditPolicy
	report.Findings = append(report.Findings, auditFindings...)

	// Detect eBPF probes
	ebProbes, ebpfFindings, err := ts.DetectEBProbes()
	if err != nil {
		return report, fmt.Errorf("failed to detect eBPF probes: %w", err)
	}
	report.EBProbes = ebProbes
	report.Findings = append(report.Findings, ebpfFindings...)

	// Detect SIEM integration
	siemIntegration, logSinks, siemFindings, err := ts.DetectSIEMIntegration()
	if err != nil {
		return report, fmt.Errorf("failed to detect SIEM integration: %w", err)
	}
	report.SIEMIntegration = siemIntegration
	report.LogSinks = logSinks
	report.Findings = append(report.Findings, siemFindings...)

	// Detect log retention
	retentionFindings, err := ts.DetectLogRetention()
	if err != nil {
		return report, fmt.Errorf("failed to detect log retention: %w", err)
	}
	report.Findings = append(report.Findings, retentionFindings...)

	// Analyze coverage
	summary, recommendations, err := ts.AnalyzeTelemetryCoverage()
	if err != nil {
		return report, fmt.Errorf("failed to analyze telemetry coverage: %w", err)
	}
	report.Summary = summary
	report.Recommendations = recommendations

	return report, nil
}

// GenerateLabResources generates lab resources for testing
func (ts *TelemetryScanner) GenerateLabResources() error {
	// Generate audit policy
	auditPolicy, err := ts.GenerateAuditPolicy()
	if err != nil {
		return fmt.Errorf("failed to generate audit policy: %w", err)
	}

	// Generate eBPF probe configs
	ebProbes, err := ts.GenerateEBProbeConfig()
	if err != nil {
		return fmt.Errorf("failed to generate eBPF probe configs: %w", err)
	}

	// Create lab directory
	labDir := "k05-telemetry-lab"
	if err := os.MkdirAll(labDir, 0755); err != nil {
		return fmt.Errorf("failed to create lab directory: %w", err)
	}

	// Write audit policy
	auditPolicyFile := filepath.Join(labDir, "audit-policy.yaml")
	if err := ts.writeAuditPolicy(auditPolicy, auditPolicyFile); err != nil {
		return fmt.Errorf("failed to write audit policy: %w", err)
	}

	// Write eBPF configs
	for _, probe := range ebProbes {
		configFile := filepath.Join(labDir, fmt.Sprintf("%s-config.yaml", probe.Name))
		if err := ts.writeEBProbeConfig(probe, configFile); err != nil {
			return fmt.Errorf("failed to write eBPF probe config: %w", err)
		}
	}

	// Write README
	readmeFile := filepath.Join(labDir, "README.md")
	if err := ts.writeLabREADME(readmeFile); err != nil {
		return fmt.Errorf("failed to write lab README: %w", err)
	}

	fmt.Printf("✅ Lab resources generated in %s/\n", labDir)
	return nil
}

// writeAuditPolicy writes audit policy to file
func (ts *TelemetryScanner) writeAuditPolicy(policy AuditPolicy, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# Kubernetes Audit Policy\n")
	fmt.Fprintf(file, "# Generated by KubeShadow K05 - Inadequate Logging and Monitoring\n\n")
	fmt.Fprintf(file, "apiVersion: audit.k8s.io/v1\n")
	fmt.Fprintf(file, "kind: Policy\n")
	fmt.Fprintf(file, "rules:\n")

	for _, rule := range policy.Rules {
		fmt.Fprintf(file, "- level: %s\n", rule.Level)
		if len(rule.Namespaces) > 0 {
			fmt.Fprintf(file, "  namespaces: [%s]\n", strings.Join(rule.Namespaces, ", "))
		}
		if len(rule.Users) > 0 {
			fmt.Fprintf(file, "  users: [%s]\n", strings.Join(rule.Users, ", "))
		}
		if len(rule.Verbs) > 0 {
			fmt.Fprintf(file, "  verbs: [%s]\n", strings.Join(rule.Verbs, ", "))
		}
		if len(rule.Resources) > 0 {
			fmt.Fprintf(file, "  resources: [%s]\n", strings.Join(rule.Resources, ", "))
		}
		fmt.Fprintf(file, "\n")
	}

	return nil
}

// writeEBProbeConfig writes eBPF probe configuration to file
func (ts *TelemetryScanner) writeEBProbeConfig(probe EBProbe, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# %s Configuration\n", strings.Title(probe.Name))
	fmt.Fprintf(file, "# Generated by KubeShadow K05 - Inadequate Logging and Monitoring\n\n")

	if probe.Type == "security" {
		fmt.Fprintf(file, "apiVersion: v1\n")
		fmt.Fprintf(file, "kind: ConfigMap\n")
		fmt.Fprintf(file, "metadata:\n")
		fmt.Fprintf(file, "  name: %s-config\n", probe.Name)
		fmt.Fprintf(file, "  namespace: %s\n", probe.Namespace)
		fmt.Fprintf(file, "data:\n")
		fmt.Fprintf(file, "  %s.yaml: |\n", probe.Name)
		for key, value := range probe.Config {
			fmt.Fprintf(file, "    %s: %s\n", key, value)
		}
	} else {
		fmt.Fprintf(file, "# %s eBPF Probe Configuration\n", probe.Name)
		fmt.Fprintf(file, "type: %s\n", probe.Type)
		fmt.Fprintf(file, "enabled: %t\n", probe.Enabled)
		fmt.Fprintf(file, "namespace: %s\n", probe.Namespace)
		fmt.Fprintf(file, "config:\n")
		for key, value := range probe.Config {
			fmt.Fprintf(file, "  %s: %s\n", key, value)
		}
	}

	return nil
}

// writeLabREADME writes lab README file
func (ts *TelemetryScanner) writeLabREADME(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "# K05 - Inadequate Logging and Monitoring Lab\n\n")
	fmt.Fprintf(file, "This lab environment demonstrates telemetry and logging security issues in Kubernetes.\n\n")
	fmt.Fprintf(file, "## Files Generated\n\n")
	fmt.Fprintf(file, "- `audit-policy.yaml`: Kubernetes audit policy configuration\n")
	fmt.Fprintf(file, "- `falco-security-config.yaml`: Falco eBPF security monitoring configuration\n")
	fmt.Fprintf(file, "- `tetragon-observability-config.yaml`: Tetragon eBPF observability configuration\n\n")
	fmt.Fprintf(file, "## Lab Setup\n\n")
	fmt.Fprintf(file, "1. Apply the audit policy to your cluster\n")
	fmt.Fprintf(file, "2. Deploy Falco with the provided configuration\n")
	fmt.Fprintf(file, "3. Deploy Tetragon for additional observability\n")
	fmt.Fprintf(file, "4. Configure SIEM integration\n\n")
	fmt.Fprintf(file, "## Testing\n\n")
	fmt.Fprintf(file, "Run KubeShadow K05 module to test detection:\n")
	fmt.Fprintf(file, "```bash\n")
	fmt.Fprintf(file, "kubeshadow owasp k05 --simulate --lab\n")
	fmt.Fprintf(file, "```\n\n")
	fmt.Fprintf(file, "## Remediation\n\n")
	fmt.Fprintf(file, "1. Enable comprehensive audit logging\n")
	fmt.Fprintf(file, "2. Deploy eBPF-based security monitoring\n")
	fmt.Fprintf(file, "3. Integrate with SIEM solutions\n")
	fmt.Fprintf(file, "4. Configure log retention policies\n")

	return nil
}

// Helper functions for output formatting
func outputJSON(report TelemetryReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputYAML(report TelemetryReport) error {
	// Simple YAML output (in a real implementation, use yaml.Marshal)
	fmt.Printf("---\n")
	fmt.Printf("findings: %d\n", len(report.Findings))
	fmt.Printf("summary:\n")
	fmt.Printf("  totalFindings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  criticalCount: %d\n", report.Summary.CriticalCount)
	fmt.Printf("  highCount: %d\n", report.Summary.HighCount)
	fmt.Printf("  mediumCount: %d\n", report.Summary.MediumCount)
	fmt.Printf("  lowCount: %d\n", report.Summary.LowCount)
	fmt.Printf("  coverageScore: %.2f\n", report.Summary.CoverageScore)
	fmt.Printf("  retentionScore: %.2f\n", report.Summary.RetentionScore)
	fmt.Printf("  auditEnabled: %t\n", report.Summary.AuditEnabled)
	fmt.Printf("  ebpfEnabled: %t\n", report.Summary.EBPFEnabled)
	fmt.Printf("  siemIntegration: %t\n", report.Summary.SIEMIntegration)
	return nil
}

func outputTable(report TelemetryReport) error {
	fmt.Printf("🔍 K05 - Inadequate Logging and Monitoring Analysis\n")
	fmt.Printf("==================================================\n\n")

	// Summary
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Total Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Printf("  Coverage Score: %.1f%%\n", report.Summary.CoverageScore)
	fmt.Printf("  Retention Score: %.1f%%\n", report.Summary.RetentionScore)
	fmt.Printf("  Audit Enabled: %t\n", report.Summary.AuditEnabled)
	fmt.Printf("  eBPF Enabled: %t\n", report.Summary.EBPFEnabled)
	fmt.Printf("  SIEM Integration: %t\n\n", report.Summary.SIEMIntegration)

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

func filterBySeverity(report TelemetryReport, severity string) TelemetryReport {
	var filteredFindings []TelemetryFinding
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
	TelemetryCmd.Flags().String("output", "table", "Output format (table, json, yaml)")
	TelemetryCmd.Flags().String("namespace", "", "Kubernetes namespace to scan")
	TelemetryCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file")
	TelemetryCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	TelemetryCmd.Flags().Bool("simulate", false, "Run detection pipeline simulation")
	TelemetryCmd.Flags().Bool("lab", false, "Generate lab resources for testing")
}
