package k08_secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var SecretsCmd = &cobra.Command{
	Use:   "k08",
	Short: "K08 - Secrets Management Failures",
	Long: `Detect raw secrets in environment variables, ConfigMaps misused for secrets, unencrypted etcd, missing KMS encryption, and exposed vaults.

This module helps identify secrets management vulnerabilities in Kubernetes environments:
- Raw secrets in environment variables and ConfigMaps
- Unencrypted etcd and missing KMS encryption
- Exposed vault configurations
- Weak image pull secrets
- Secret exfiltration simulation

Examples:
  kubeshadow owasp k08 --output json
  kubeshadow owasp k08 --simulate --lab --confirm
  kubeshadow owasp k08 --namespace production --severity critical`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		output, _ := cmd.Flags().GetString("output")
		namespace, _ := cmd.Flags().GetString("namespace")
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		severity, _ := cmd.Flags().GetString("severity")
		simulate, _ := cmd.Flags().GetBool("simulate")
		lab, _ := cmd.Flags().GetBool("lab")
		confirm, _ := cmd.Flags().GetBool("confirm")

		// Create scanner
		scanner, err := NewSecretScanner(kubeconfig, namespace, lab, confirm)
		if err != nil {
			return fmt.Errorf("failed to create secrets scanner: %w", err)
		}

		// Run secrets analysis
		report, err := scanner.RunSecretsAnalysis()
		if err != nil {
			return fmt.Errorf("failed to run secrets analysis: %w", err)
		}

		// Filter by severity if specified
		if severity != "" {
			report = filterBySeverity(report, severity)
		}

		// Run simulation if requested
		if simulate {
			exfiltrationTests, err := scanner.SimulateSecretExfiltration()
			if err != nil {
				return fmt.Errorf("failed to run secret exfiltration simulation: %w", err)
			}
			report.ExfiltrationTests = exfiltrationTests

			// Run secret detection tests in lab mode
			if lab {
				detectionTests, err := scanner.TestSecretDetection()
				if err != nil {
					return fmt.Errorf("failed to run secret detection tests: %w", err)
				}
				report.Findings = append(report.Findings, detectionTests...)

				// Run secret rotation simulation
				rotationTests, err := scanner.SimulateSecretRotation()
				if err != nil {
					return fmt.Errorf("failed to run secret rotation simulation: %w", err)
				}
				report.Findings = append(report.Findings, rotationTests...)
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

// RunSecretsAnalysis runs the complete secrets analysis
func (ss *SecretScanner) RunSecretsAnalysis() (SecretReport, error) {
	report := SecretReport{
		GeneratedAt: time.Now(),
	}

	// Detect raw secrets
	secrets, configMapSecrets, secretFindings, err := ss.DetectRawSecrets()
	if err != nil {
		return report, fmt.Errorf("failed to detect raw secrets: %w", err)
	}
	report.Secrets = secrets
	report.ConfigMapSecrets = configMapSecrets
	report.Findings = append(report.Findings, secretFindings...)

	// Detect image pull secrets
	imagePullSecrets, imagePullFindings, err := ss.DetectImagePullSecrets()
	if err != nil {
		return report, fmt.Errorf("failed to detect image pull secrets: %w", err)
	}
	report.ImagePullSecrets = imagePullSecrets
	report.Findings = append(report.Findings, imagePullFindings...)

	// Detect etcd encryption
	etcdEncryption, etcdFindings, err := ss.DetectEtcdEncryption()
	if err != nil {
		return report, fmt.Errorf("failed to detect etcd encryption: %w", err)
	}
	report.EtcdEncryption = etcdEncryption
	report.Findings = append(report.Findings, etcdFindings...)

	// Detect KMS encryption
	kmsEncryption, kmsFindings, err := ss.DetectKMSEncryption()
	if err != nil {
		return report, fmt.Errorf("failed to detect KMS encryption: %w", err)
	}
	report.KMSEncryption = kmsEncryption
	report.Findings = append(report.Findings, kmsFindings...)

	// Detect vaults
	vaults, vaultFindings, err := ss.DetectVaults()
	if err != nil {
		return report, fmt.Errorf("failed to detect vaults: %w", err)
	}
	report.Vaults = vaults
	report.Findings = append(report.Findings, vaultFindings...)

	// Analyze secret management
	summary, recommendations, err := ss.AnalyzeSecretManagement()
	if err != nil {
		return report, fmt.Errorf("failed to analyze secret management: %w", err)
	}
	report.Summary = summary
	report.Recommendations = recommendations

	// Additional security evaluations
	secretSecurityFindings := ss.EvaluateSecretSecurity()
	report.Findings = append(report.Findings, secretSecurityFindings...)

	return report, nil
}

// Helper functions for output formatting
func outputJSON(report SecretReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputYAML(report SecretReport) error {
	// Simple YAML output (in a real implementation, use yaml.Marshal)
	fmt.Printf("---\n")
	fmt.Printf("findings: %d\n", len(report.Findings))
	fmt.Printf("summary:\n")
	fmt.Printf("  totalFindings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  criticalCount: %d\n", report.Summary.CriticalCount)
	fmt.Printf("  highCount: %d\n", report.Summary.HighCount)
	fmt.Printf("  mediumCount: %d\n", report.Summary.MediumCount)
	fmt.Printf("  lowCount: %d\n", report.Summary.LowCount)
	fmt.Printf("  secretScore: %.2f\n", report.Summary.SecretScore)
	fmt.Printf("  rawSecretsFound: %d\n", report.Summary.RawSecretsFound)
	fmt.Printf("  configMapSecrets: %d\n", report.Summary.ConfigMapSecrets)
	fmt.Printf("  etcdEncryptionEnabled: %t\n", report.Summary.EtcdEncryptionEnabled)
	fmt.Printf("  kmsEncryptionEnabled: %t\n", report.Summary.KMSEncryptionEnabled)
	return nil
}

func outputTable(report SecretReport) error {
	fmt.Printf("🔐 K08 - Secrets Management Failures Analysis\n")
	fmt.Printf("==============================================\n\n")

	// Summary
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Total Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Printf("  Secret Score: %.1f%%\n", report.Summary.SecretScore)
	fmt.Printf("  Raw Secrets Found: %d\n", report.Summary.RawSecretsFound)
	fmt.Printf("  ConfigMap Secrets: %d\n", report.Summary.ConfigMapSecrets)
	fmt.Printf("  Exposed Secrets: %d\n", report.Summary.ExposedSecrets)
	fmt.Printf("  Etcd Encryption: %t\n", report.Summary.EtcdEncryptionEnabled)
	fmt.Printf("  KMS Encryption: %t\n", report.Summary.KMSEncryptionEnabled)
	fmt.Printf("\n")

	// Encryption Status
	fmt.Printf("🔒 Encryption Status:\n")
	fmt.Printf("  Etcd Encryption: %t\n", report.EtcdEncryption.Enabled)
	if report.EtcdEncryption.Enabled {
		fmt.Printf("  Providers: %s\n", strings.Join(report.EtcdEncryption.Providers, ", "))
	}
	fmt.Printf("  KMS Encryption: %t\n", report.KMSEncryption.Enabled)
	if report.KMSEncryption.Enabled {
		fmt.Printf("  Provider: %s\n", report.KMSEncryption.Provider)
	}
	fmt.Printf("\n")

	// Raw Secrets
	if len(report.Secrets) > 0 {
		fmt.Printf("🔍 Raw Secrets Found: %d\n", len(report.Secrets))
		for _, secret := range report.Secrets {
			if secret.Exposed {
				fmt.Printf("  %s/%s (%s) - %s\n", secret.Namespace, secret.Name, secret.Type, secret.RedactedValue)
			}
		}
		fmt.Printf("\n")
	}

	// ConfigMap Secrets
	if len(report.ConfigMapSecrets) > 0 {
		fmt.Printf("⚠️ Secrets in ConfigMaps: %d\n", len(report.ConfigMapSecrets))
		for _, cmSecret := range report.ConfigMapSecrets {
			fmt.Printf("  %s/%s.%s - %s\n", cmSecret.Namespace, cmSecret.ConfigMapName, cmSecret.Key, cmSecret.RedactedValue)
		}
		fmt.Printf("\n")
	}

	// Vaults
	if len(report.Vaults) > 0 {
		fmt.Printf("🏦 Vault Configurations: %d\n", len(report.Vaults))
		for _, vault := range report.Vaults {
			fmt.Printf("  %s (%s) - %s\n", vault.Name, vault.Type, vault.URL)
		}
		fmt.Printf("\n")
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

	// Exfiltration Tests
	if len(report.ExfiltrationTests) > 0 {
		fmt.Printf("🧪 Secret Exfiltration Tests:\n")
		for _, test := range report.ExfiltrationTests {
			fmt.Printf("  %s: %s\n", test.SecretName, test.Description)
			fmt.Printf("    Method: %s\n", test.Method)
			fmt.Printf("    Destination: %s\n", test.Destination)
			fmt.Printf("    Risk Level: %s\n", test.RiskLevel)
		}
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

func filterBySeverity(report SecretReport, severity string) SecretReport {
	var filteredFindings []SecretFinding
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
	SecretsCmd.Flags().String("output", "table", "Output format (table, json, yaml)")
	SecretsCmd.Flags().String("namespace", "", "Kubernetes namespace to scan")
	SecretsCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file")
	SecretsCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	SecretsCmd.Flags().Bool("simulate", false, "Run secret exfiltration simulation and tests")
	SecretsCmd.Flags().Bool("lab", false, "Enable lab mode for safe secret testing")
	SecretsCmd.Flags().Bool("confirm", false, "Confirm secret value exposure (lab mode only)")
}
