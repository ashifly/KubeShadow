package k07_network

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var NetworkCmd = &cobra.Command{
	Use:   "k07",
	Short: "K07 - Missing Network Segmentation Controls",
	Long: `Detect lack of NetworkPolicies, hostNetwork usage, overly broad service exposure, and CNI misconfigurations.

This module helps identify network segmentation vulnerabilities in Kubernetes environments:
- NetworkPolicy configuration and coverage
- Host network usage and security implications
- Public service exposure (NodePort/LoadBalancer)
- CNI configuration and capabilities
- Network connectivity and blast radius analysis

Examples:
  kubeshadow owasp k07 --output json
  kubeshadow owasp k07 --simulate --lab
  kubeshadow owasp k07 --namespace production --severity high`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		output, _ := cmd.Flags().GetString("output")
		namespace, _ := cmd.Flags().GetString("namespace")
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		severity, _ := cmd.Flags().GetString("severity")
		simulate, _ := cmd.Flags().GetBool("simulate")
		lab, _ := cmd.Flags().GetBool("lab")

		// Create scanner
		scanner, err := NewNetworkScanner(kubeconfig, namespace, lab)
		if err != nil {
			return fmt.Errorf("failed to create network scanner: %w", err)
		}

		// Run network analysis
		report, err := scanner.RunNetworkAnalysis()
		if err != nil {
			return fmt.Errorf("failed to run network analysis: %w", err)
		}

		// Filter by severity if specified
		if severity != "" {
			report = filterBySeverity(report, severity)
		}

		// Run simulation if requested
		if simulate {
			connectivityTests, err := scanner.SimulateNetworkTests()
			if err != nil {
				return fmt.Errorf("failed to run network tests: %w", err)
			}
			report.ConnectivityTests = connectivityTests

			// Run network probes in lab mode
			if lab {
				networkProbes, err := scanner.SimulateNetworkProbes()
				if err != nil {
					return fmt.Errorf("failed to run network probes: %w", err)
				}
				report.ConnectivityTests = append(report.ConnectivityTests, networkProbes...)
			}
		}

		// Analyze blast radius
		blastRadius, err := scanner.AnalyzeBlastRadius("test-pod", "default")
		if err == nil {
			report.BlastRadius = append(report.BlastRadius, blastRadius)
		}

		// Build network matrix
		networkMatrix, err := scanner.BuildNetworkMatrix()
		if err == nil {
			report.NetworkMatrix = networkMatrix
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

// RunNetworkAnalysis runs the complete network analysis
func (ns *NetworkScanner) RunNetworkAnalysis() (NetworkReport, error) {
	report := NetworkReport{
		GeneratedAt: time.Now(),
	}

	// Detect NetworkPolicies
	networkPolicies, policyFindings, err := ns.DetectNetworkPolicies()
	if err != nil {
		return report, fmt.Errorf("failed to detect network policies: %w", err)
	}
	report.NetworkPolicies = networkPolicies
	report.Findings = append(report.Findings, policyFindings...)

	// Detect host network pods
	hostNetworkPods, hostFindings, err := ns.DetectHostNetworkPods()
	if err != nil {
		return report, fmt.Errorf("failed to detect host network pods: %w", err)
	}
	report.Pods = hostNetworkPods
	report.Findings = append(report.Findings, hostFindings...)

	// Detect public services
	publicServices, serviceFindings, err := ns.DetectPublicServices()
	if err != nil {
		return report, fmt.Errorf("failed to detect public services: %w", err)
	}
	report.Services = publicServices
	report.Findings = append(report.Findings, serviceFindings...)

	// Detect CNI configuration
	cniInfo, cniFindings, err := ns.DetectCNIConfiguration()
	if err != nil {
		return report, fmt.Errorf("failed to detect CNI configuration: %w", err)
	}
	report.CNIInfo = cniInfo
	report.Findings = append(report.Findings, cniFindings...)

	// Analyze network segmentation
	summary, recommendations, err := ns.AnalyzeNetworkSegmentation()
	if err != nil {
		return report, fmt.Errorf("failed to analyze network segmentation: %w", err)
	}
	report.Summary = summary
	report.Recommendations = recommendations

	// Additional security evaluations
	networkSecurityFindings := ns.EvaluateNetworkSecurity()
	report.Findings = append(report.Findings, networkSecurityFindings...)

	return report, nil
}

// Helper functions for output formatting
func outputJSON(report NetworkReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputYAML(report NetworkReport) error {
	// Simple YAML output (in a real implementation, use yaml.Marshal)
	fmt.Printf("---\n")
	fmt.Printf("findings: %d\n", len(report.Findings))
	fmt.Printf("summary:\n")
	fmt.Printf("  totalFindings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  criticalCount: %d\n", report.Summary.CriticalCount)
	fmt.Printf("  highCount: %d\n", report.Summary.HighCount)
	fmt.Printf("  mediumCount: %d\n", report.Summary.MediumCount)
	fmt.Printf("  lowCount: %d\n", report.Summary.LowCount)
	fmt.Printf("  networkScore: %.2f\n", report.Summary.NetworkScore)
	fmt.Printf("  networkPoliciesCount: %d\n", report.Summary.NetworkPoliciesCount)
	fmt.Printf("  hostNetworkPods: %d\n", report.Summary.HostNetworkPods)
	fmt.Printf("  publicServices: %d\n", report.Summary.PublicServices)
	fmt.Printf("  cniProvider: %s\n", report.Summary.CNIProvider)
	return nil
}

func outputTable(report NetworkReport) error {
	fmt.Printf("🌐 K07 - Missing Network Segmentation Controls Analysis\n")
	fmt.Printf("======================================================\n\n")

	// Summary
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Total Findings: %d\n", report.Summary.TotalFindings)
	fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Printf("  Network Score: %.1f%%\n", report.Summary.NetworkScore)
	fmt.Printf("  Network Policies: %d\n", report.Summary.NetworkPoliciesCount)
	fmt.Printf("  Host Network Pods: %d\n", report.Summary.HostNetworkPods)
	fmt.Printf("  Public Services: %d\n", report.Summary.PublicServices)
	fmt.Printf("  CNI Provider: %s\n", report.Summary.CNIProvider)
	fmt.Printf("  Default Deny Enabled: %t\n", report.Summary.DefaultDenyEnabled)
	fmt.Printf("  Blast Radius: %d\n", report.Summary.BlastRadius)
	fmt.Printf("\n")

	// CNI Information
	if report.CNIInfo.Provider != "" {
		fmt.Printf("🔧 CNI Configuration:\n")
		fmt.Printf("  Provider: %s\n", report.CNIInfo.Provider)
		fmt.Printf("  Features: %s\n", strings.Join(report.CNIInfo.Features, ", "))
		fmt.Printf("\n")
	}

	// Network Policies
	if len(report.NetworkPolicies) > 0 {
		fmt.Printf("🛡️ Network Policies:\n")
		for _, policy := range report.NetworkPolicies {
			fmt.Printf("  %s/%s (%d rules)\n", policy.Namespace, policy.Name, len(policy.Rules))
		}
		fmt.Printf("\n")
	}

	// Host Network Pods
	if len(report.Pods) > 0 {
		hostNetworkCount := 0
		for _, pod := range report.Pods {
			if pod.HostNetwork {
				hostNetworkCount++
			}
		}
		if hostNetworkCount > 0 {
			fmt.Printf("⚠️ Host Network Pods: %d\n", hostNetworkCount)
			for _, pod := range report.Pods {
				if pod.HostNetwork {
					fmt.Printf("  %s/%s\n", pod.Namespace, pod.Name)
				}
			}
			fmt.Printf("\n")
		}
	}

	// Public Services
	if len(report.Services) > 0 {
		publicCount := 0
		for _, svc := range report.Services {
			if svc.Public {
				publicCount++
			}
		}
		if publicCount > 0 {
			fmt.Printf("🌍 Public Services: %d\n", publicCount)
			for _, svc := range report.Services {
				if svc.Public {
					fmt.Printf("  %s/%s (%s)\n", svc.Namespace, svc.Name, svc.Type)
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

	// Connectivity Tests
	if len(report.ConnectivityTests) > 0 {
		fmt.Printf("🧪 Connectivity Tests:\n")
		successCount := 0
		for _, test := range report.ConnectivityTests {
			if test.Success {
				successCount++
			}
		}
		fmt.Printf("  Tests Run: %d\n", len(report.ConnectivityTests))
		fmt.Printf("  Successful: %d\n", successCount)
		fmt.Printf("  Failed: %d\n", len(report.ConnectivityTests)-successCount)
		fmt.Printf("\n")
	}

	// Blast Radius
	if len(report.BlastRadius) > 0 {
		fmt.Printf("💥 Blast Radius Analysis:\n")
		for _, br := range report.BlastRadius {
			fmt.Printf("  Pod: %s/%s\n", br.Namespace, br.PodName)
			fmt.Printf("    Reachable Pods: %d\n", br.ReachablePods)
			fmt.Printf("    Reachable Services: %d\n", br.ReachableServices)
			fmt.Printf("    Risk Level: %s\n", br.RiskLevel)
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

func filterBySeverity(report NetworkReport, severity string) NetworkReport {
	var filteredFindings []NetworkFinding
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
	NetworkCmd.Flags().String("output", "table", "Output format (table, json, yaml)")
	NetworkCmd.Flags().String("namespace", "", "Kubernetes namespace to scan")
	NetworkCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file")
	NetworkCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	NetworkCmd.Flags().Bool("simulate", false, "Run network connectivity tests and simulations")
	NetworkCmd.Flags().Bool("lab", false, "Enable lab mode for safe network testing")
}
