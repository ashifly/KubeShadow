package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
)

// RBACCmd represents the K03 RBAC command
var RBACCmd = &cobra.Command{
	Use:   "k03",
	Short: "K03 - Overly Permissive RBAC Configurations",
	Long: `K03 - Overly Permissive RBAC Configurations

This command analyzes RBAC configurations for privilege escalation paths and overly permissive bindings.

Features:
- Detector: Enumerates Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, ServiceAccounts
- Analyzer: Computes escalation paths and risk scores using graph algorithms
- Simulator: Generates lab demonstrations of privilege escalation scenarios
- Outputs: rbac_graph.json with graph format and prioritized risky bindings

Examples:
  kubeshadow owasp k03
  kubeshadow owasp k03 --namespace kube-system
  kubeshadow owasp k03 --output ./rbac-report.json
  kubeshadow owasp k03 --lab --simulate
  kubeshadow owasp k03 --severity critical,high`,
	RunE: runRBAC,
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
	RBACCmd.Flags().StringVarP(&outputPath, "output", "o", "./rbac_graph.json", "Output file path for RBAC graph")
	RBACCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Scan specific namespace (default: all namespaces)")
	RBACCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by severity levels (comma-separated: critical,high,medium,low)")
	RBACCmd.Flags().BoolVar(&labMode, "lab", false, "Enable lab mode for non-destructive testing")
	RBACCmd.Flags().BoolVar(&simulate, "simulate", false, "Run simulation to demonstrate privilege escalation (requires --lab)")
	RBACCmd.Flags().BoolVar(&applyChanges, "apply", false, "Apply changes in lab mode (DANGEROUS - only use in lab)")
	RBACCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: ~/.kube/config)")
}

func runRBAC(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger.Info("🔒 Starting K03 - Overly Permissive RBAC Configurations scan...")

	// Create scanner
	scanner, err := NewRBACScanner(ctx, kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create RBAC scanner: %v", err)
	}

	// Collect RBAC data
	logger.Info("📊 Collecting RBAC data...")
	data, err := scanner.CollectRBACData(namespace)
	if err != nil {
		return fmt.Errorf("failed to collect RBAC data: %v", err)
	}

	// Build RBAC graph
	logger.Info("🕸️  Building RBAC graph...")
	graph := scanner.BuildGraph(data)

	// Analyze RBAC configuration
	logger.Info("🔍 Analyzing RBAC configuration...")
	findings := scanner.AnalyzeRBAC(data)

	// Filter findings if needed
	if severityFilter != "" {
		findings = filterBySeverity(findings, severityFilter)
	}

	// Print summary
	printSummary(findings, graph)

	// Run simulation if requested
	if labMode {
		if simulate {
			logger.Info("🧪 Running RBAC simulation...")
			if err := scanner.RunSimulation(ctx, findings); err != nil {
				logger.Warn("Simulation failed: %v", err)
			}
		}

		if applyChanges {
			logger.Info("⚠️  Applying lab environment changes...")
			if err := scanner.CreateLabEnvironment(ctx); err != nil {
				logger.Warn("Failed to create lab environment: %v", err)
			}
		}
	}

	// Save results
	if err := saveResults(graph, findings, outputPath); err != nil {
		return fmt.Errorf("failed to save results: %v", err)
	}

	logger.Info("✅ RBAC configuration scan completed!")
	return nil
}

func printSummary(findings []RBACFinding, graph *RBACGraph) {
	logger.Info("📊 RBAC SECURITY SCAN SUMMARY")
	logger.Info("==================================================")

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

	logger.Info("🔍 Total RBAC Resources: %d", len(graph.Nodes))
	logger.Info("🔗 Total RBAC Relationships: %d", len(graph.Edges))
	logger.Info("🔴 Critical: %d", critical)
	logger.Info("🟠 High: %d", high)
	logger.Info("🟡 Medium: %d", medium)
	logger.Info("🟢 Low: %d", low)
	logger.Info("📈 Average Risk Score: %.2f", totalRisk/float64(len(findings)))
	logger.Info("")

	// Show top findings
	if len(findings) > 0 {
		logger.Info("🚨 TOP RBAC FINDINGS:")
		logger.Info("")

		// Sort by risk score (simplified - just show first 5)
		maxShow := 5
		if len(findings) < maxShow {
			maxShow = len(findings)
		}

		for i := 0; i < maxShow; i++ {
			finding := findings[i]
			logger.Info("  %d. %s (%s) - Risk: %.2f",
				i+1, finding.Subject, finding.Severity, finding.RiskScore)
			logger.Info("     Role: %s (%s)", finding.Role, finding.RoleType)
			if len(finding.EscalationPaths) > 0 {
				logger.Info("     ⚠️  %d Escalation Paths", len(finding.EscalationPaths))
			}
		}
	}

	// Show risky bindings
	riskyBindings := getRiskyBindings(findings)
	if len(riskyBindings) > 0 {
		logger.Info("")
		logger.Info("🎯 PRIORITIZED RISKY BINDINGS:")
		for i, binding := range riskyBindings {
			if i >= 3 { // Show top 3
				break
			}
			logger.Info("  %d. %s -> %s (Risk: %.2f)",
				i+1, binding.Subject, binding.Role, binding.RiskScore)
			logger.Info("     Reason: %s", binding.Reason)
		}
	}
}

func filterBySeverity(findings []RBACFinding, severityFilter string) []RBACFinding {
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

	var filtered []RBACFinding
	for _, finding := range findings {
		if severities[strings.ToLower(finding.Severity)] {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func getRiskyBindings(findings []RBACFinding) []RiskyBinding {
	var risky []RiskyBinding

	for _, finding := range findings {
		if finding.RiskScore > 0.5 {
			risky = append(risky, RiskyBinding{
				Subject:     finding.Subject,
				Role:        finding.Role,
				RiskScore:   finding.RiskScore,
				Reason:      fmt.Sprintf("High risk permissions in %s", finding.RoleType),
				Remediation: finding.Remediation.Description,
			})
		}
	}

	return risky
}

func saveResults(graph *RBACGraph, findings []RBACFinding, outputPath string) error {
	result := map[string]interface{}{
		"graph":    graph,
		"findings": findings,
		"summary": map[string]interface{}{
			"totalNodes":    len(graph.Nodes),
			"totalEdges":    len(graph.Edges),
			"totalFindings": len(findings),
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
