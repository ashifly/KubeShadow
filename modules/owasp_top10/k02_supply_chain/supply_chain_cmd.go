package supply_chain

import (
	"context"
	"fmt"
	"strings"

	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
)

// SupplyChainCmd represents the K02 supply chain command
var SupplyChainCmd = &cobra.Command{
	Use:   "k02",
	Short: "K02 - Supply Chain Vulnerabilities",
	Long: `K02 - Supply Chain Vulnerabilities

This command detects risky images, mutable registries, weak CI pipelines, 
GitOps misconfigurations, and image provenance gaps in your Kubernetes cluster.

Features:
- Detector: Enumerates images from PodSpecs, fetches image digests, queries 
  SBOM/scan results (Trivy/Grype integration), checks for public/mutable 
  registries, checks image tag patterns (e.g., :latest), and detects 
  imagePullSecrets usage
- Analyzer: Ranks by CVEs, presence of signed provenance (cosign), registry 
  exposure (anonymous push), and whether the image is used in many namespaces
- Simulator: Creates a harmless mutated image stub in lab (only in --lab), 
  or generates a "what-if" manifest showing how a supply-chain compromise 
  would propagate
- Outputs: supplychain_report.json + recommended CI/GitOps hardening steps

Examples:
  kubeshadow owasp k02
  kubeshadow owasp k02 --trivy-url http://trivy:8080
  kubeshadow owasp k02 --output ./supplychain-report.json
  kubeshadow owasp k02 --lab --simulate
  kubeshadow owasp k02 --namespace kube-system
  kubeshadow owasp k02 --severity critical,high`,
	RunE: runSupplyChain,
}

var (
	outputPath     string
	trivyURL       string
	namespace      string
	severityFilter string
	labMode        bool
	simulate       bool
	kubeconfig     string
)

func init() {
	SupplyChainCmd.Flags().StringVarP(&outputPath, "output", "o", "./supplychain_report.json", "Output file path for findings")
	SupplyChainCmd.Flags().StringVar(&trivyURL, "trivy-url", "", "Trivy server URL for vulnerability scanning")
	SupplyChainCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Scan specific namespace (default: all namespaces)")
	SupplyChainCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by severity levels (comma-separated: critical,high,medium,low)")
	SupplyChainCmd.Flags().BoolVar(&labMode, "lab", false, "Enable lab mode for non-destructive testing")
	SupplyChainCmd.Flags().BoolVar(&simulate, "simulate", false, "Run simulation to demonstrate potential impact (requires --lab)")
	SupplyChainCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: ~/.kube/config)")
}

func runSupplyChain(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger.Info("🔗 Starting K02 - Supply Chain Vulnerabilities scan...")

	// Create scanner
	scanner, err := NewSupplyChainScanner(ctx, kubeconfig, trivyURL)
	if err != nil {
		return fmt.Errorf("failed to create supply chain scanner: %v", err)
	}

	// Scan supply chain
	logger.Info("📊 Scanning container images for supply chain vulnerabilities...")
	findings, err := scanner.ScanSupplyChain()
	if err != nil {
		return fmt.Errorf("failed to scan supply chain: %v", err)
	}

	// Filter findings if needed
	if severityFilter != "" {
		findings = filterBySeverity(findings, severityFilter)
	}

	if namespace != "" {
		findings = filterByNamespace(findings, namespace)
	}

	// Print summary
	printSummary(findings)

	// Run simulation if requested
	if labMode && simulate {
		logger.Info("🧪 Running lab simulation...")
		if err := runSimulation(ctx, scanner, findings); err != nil {
			logger.Warn("Simulation failed: %v", err)
		}
	}

	// Save findings
	if err := scanner.SaveFindingsToFile(findings, outputPath); err != nil {
		return fmt.Errorf("failed to save findings: %v", err)
	}

	logger.Info("✅ Supply chain vulnerability scan completed!")
	return nil
}

func printSummary(findings []SupplyChainFinding) {
	logger.Info("📊 SUPPLY CHAIN SECURITY SCAN SUMMARY")
	logger.Info("==================================================")

	// Count by severity
	critical := 0
	high := 0
	medium := 0
	low := 0
	totalRisk := 0.0
	totalVulns := 0

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
		totalVulns += len(finding.Vulnerabilities)
	}

	logger.Info("🔍 Total Images Scanned: %d", len(findings))
	logger.Info("🔴 Critical: %d", critical)
	logger.Info("🟠 High: %d", high)
	logger.Info("🟡 Medium: %d", medium)
	logger.Info("🟢 Low: %d", low)
	logger.Info("📈 Total Vulnerabilities: %d", totalVulns)
	logger.Info("📊 Average Risk Score: %.2f", totalRisk/float64(len(findings)))
	logger.Info("")

	// Show top findings
	if len(findings) > 0 {
		logger.Info("🚨 TOP SUPPLY CHAIN FINDINGS:")
		logger.Info("")

		// Sort by risk score (simplified - just show first 5)
		maxShow := 5
		if len(findings) < maxShow {
			maxShow = len(findings)
		}

		for i := 0; i < maxShow; i++ {
			finding := findings[i]
			logger.Info("  %d. %s (%s) - Risk: %.2f",
				i+1, finding.ImageName, finding.Severity, finding.RiskScore)

			if finding.RegistryInfo.IsPublic {
				logger.Info("     ⚠️  Public Registry")
			}
			if finding.RegistryInfo.IsMutable {
				logger.Info("     ⚠️  Mutable Registry")
			}
			if !finding.ProvenanceInfo.HasSignature {
				logger.Info("     ⚠️  No Image Signature")
			}
			if len(finding.Vulnerabilities) > 0 {
				logger.Info("     ⚠️  %d Vulnerabilities", len(finding.Vulnerabilities))
			}
		}
	}
}

func filterBySeverity(findings []SupplyChainFinding, severityFilter string) []SupplyChainFinding {
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

	var filtered []SupplyChainFinding
	for _, finding := range findings {
		if severities[strings.ToLower(finding.Severity)] {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func filterByNamespace(findings []SupplyChainFinding, targetNamespace string) []SupplyChainFinding {
	var filtered []SupplyChainFinding
	for _, finding := range findings {
		if finding.Namespace == targetNamespace {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func runSimulation(_ context.Context, _ *SupplyChainScanner, _ []SupplyChainFinding) error {
	logger.Info("🧪 Starting supply chain simulation...")

	// Create a mock "compromised" image manifest
	simulationManifest := `
apiVersion: v1
kind: Pod
metadata:
  name: supply-chain-simulation
  namespace: default
  labels:
    app: kubeshadow-simulation
spec:
  containers:
  - name: simulation
    image: alpine:latest
    command: ["sh", "-c"]
    args:
    - echo '🔗 KubeShadow Supply Chain Simulator'
    - echo '📊 Demonstrating supply chain attack vectors...'
    - echo '⚠️  This is a simulation - no actual harm done'
    - echo '🔍 Showing how compromised images could propagate'
    - sleep 30
    - echo '✅ Simulation completed'
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
  restartPolicy: Never
`

	logger.Info("📄 Simulation Manifest:")
	logger.Info("%s", simulationManifest)
	logger.Info("")
	logger.Info("💡 This demonstrates how a supply chain compromise could propagate")
	logger.Info("🛡️  Real-world protection requires:")
	logger.Info("   • Image signing and verification")
	logger.Info("   • Vulnerability scanning")
	logger.Info("   • SBOM generation and verification")
	logger.Info("   • Registry security policies")

	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			strings.Contains(s, substr))))
}
