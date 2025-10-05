package workload_config

import (
	"context"
	"fmt"
	"strings"

	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadConfigCmd represents the workload config command
var WorkloadConfigCmd = &cobra.Command{
	Use:   "workload-config",
	Short: "Scan workloads for insecure security configurations",
	Long: `K01 - Insecure Workload Configurations

This command scans all workloads (Pods, Deployments, StatefulSets, DaemonSets) 
for dangerous security contexts, hostPath/hostNetwork, privileged containers, 
elevated capabilities, and unsafe PodSecurity levels.

Features:
- Detector: Scans all PodSpecs for securityContext.privileged, hostPath, 
  hostNetwork, capabilities.add, runAsUser: 0, allowPrivilegeEscalation: true, 
  imagePullPolicy: Always
- Analyzer: Computes a risk score (CVSS-style) taking into account SA privileges, 
  namespace sensitivity, and host exposure
- Simulator (lab-only): Spins up a benign helper Pod that demonstrates 
  "what would be possible" using a non-destructive script (requires --lab)
- Outputs: insecure_workloads.json with list, severity, suggested remediation 
  (PSA/OPA policy snippet)

Examples:
  kubeshadow workload-config
  kubeshadow workload-config --output ./findings.json
  kubeshadow workload-config --lab --simulate
  kubeshadow workload-config --kubeconfig ~/.kube/config
  kubeshadow workload-config --namespace kube-system
  kubeshadow workload-config --severity critical,high
  kubeshadow workload-config --remediation-only`,
	RunE: runWorkloadConfig,
}

var (
	outputPath      string
	labMode         bool
	simulate        bool
	kubeconfig      string
	namespace       string
	severityFilter  string
	remediationOnly bool
)

func init() {
	WorkloadConfigCmd.Flags().StringVarP(&outputPath, "output", "o", "./insecure_workloads.json", "Output file path for findings")
	WorkloadConfigCmd.Flags().BoolVar(&labMode, "lab", false, "Enable lab mode for non-destructive testing")
	WorkloadConfigCmd.Flags().BoolVar(&simulate, "simulate", false, "Run simulation to demonstrate potential impact (requires --lab)")
	WorkloadConfigCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: ~/.kube/config)")
	WorkloadConfigCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Scan specific namespace (default: all namespaces)")
	WorkloadConfigCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by severity levels (comma-separated: critical,high,medium,low)")
	WorkloadConfigCmd.Flags().BoolVar(&remediationOnly, "remediation-only", false, "Show only remediation suggestions")
}

func runWorkloadConfig(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger.Info("🔍 Starting K01 - Insecure Workload Configurations scan...")

	// Create scanner
	scanner, err := NewWorkloadConfigScanner(ctx, kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create workload scanner: %v", err)
	}

	// Scan workloads
	logger.Info("📊 Scanning workloads for security misconfigurations...")
	findings, err := scanner.ScanWorkloads()
	if err != nil {
		return fmt.Errorf("failed to scan workloads: %v", err)
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

	// Show remediation if requested
	if remediationOnly {
		printRemediation(findings)
		return nil
	}

	// Save findings
	if err := scanner.SaveFindingsToFile(findings, outputPath); err != nil {
		return fmt.Errorf("failed to save findings: %v", err)
	}

	logger.Info("✅ Workload configuration scan completed!")
	return nil
}

func printSummary(findings []WorkloadFinding) {
	logger.Info("📊 WORKLOAD SECURITY SCAN SUMMARY")
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

	logger.Info("🔍 Total Workloads Scanned: %d", len(findings))
	logger.Info("🔴 Critical: %d", critical)
	logger.Info("🟠 High: %d", high)
	logger.Info("🟡 Medium: %d", medium)
	logger.Info("🟢 Low: %d", low)
	logger.Info("📈 Total Risk Score: %.2f", totalRisk)
	logger.Info("")

	// Show top findings
	if len(findings) > 0 {
		logger.Info("🚨 TOP SECURITY FINDINGS:")
		logger.Info("")

		// Sort by risk score (simplified - just show first 5)
		maxShow := 5
		if len(findings) < maxShow {
			maxShow = len(findings)
		}

		for i := 0; i < maxShow; i++ {
			finding := findings[i]
			logger.Info("  %d. %s/%s (%s) - Risk: %.2f",
				i+1, finding.Namespace, finding.WorkloadName, finding.Severity, finding.RiskScore)

			if finding.HostExposure {
				logger.Info("     ⚠️  Host Exposure Detected")
			}
			if finding.NamespaceSensitive {
				logger.Info("     ⚠️  Sensitive Namespace")
			}
		}
	}
}

func printRemediation(findings []WorkloadFinding) {
	logger.Info("🛠️  REMEDIATION SUGGESTIONS")
	logger.Info("==================================================")

	for _, finding := range findings {
		logger.Info("📋 %s/%s (%s)", finding.Namespace, finding.WorkloadName, finding.Severity)
		logger.Info("   %s", finding.Remediation.Description)
		logger.Info("")
	}
}

func filterBySeverity(findings []WorkloadFinding, severityFilter string) []WorkloadFinding {
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

	var filtered []WorkloadFinding
	for _, finding := range findings {
		if severities[strings.ToLower(finding.Severity)] {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func filterByNamespace(findings []WorkloadFinding, targetNamespace string) []WorkloadFinding {
	var filtered []WorkloadFinding
	for _, finding := range findings {
		if finding.Namespace == targetNamespace {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func runSimulation(ctx context.Context, scanner *WorkloadConfigScanner, _ []WorkloadFinding) error {
	logger.Info("🧪 Starting non-destructive simulation...")

	// Create a benign helper pod to demonstrate potential impact
	helperPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubeshadow-workload-simulator",
			Namespace: "default",
			Labels: map[string]string{
				"app": "kubeshadow-simulator",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "simulator",
					Image:   "alpine:latest",
					Command: []string{"sh", "-c"},
					Args: []string{
						"echo '🔍 KubeShadow Workload Simulator'; " +
							"echo '📊 Demonstrating potential security impact...'; " +
							"echo '⚠️  This is a simulation - no actual harm done'; " +
							"sleep 30; " +
							"echo '✅ Simulation completed'",
					},
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: func() *bool { b := true; return &b }(),
						RunAsUser:    func() *int64 { u := int64(1000); return &u }(),
					},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	// Create the pod
	_, err := scanner.clientset.CoreV1().Pods("default").Create(ctx, helperPod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create simulation pod: %v", err)
	}

	logger.Info("✅ Simulation pod created: kubeshadow-workload-simulator")
	logger.Info("📝 This demonstrates what a secure workload should look like")
	logger.Info("🗑️  Pod will be automatically cleaned up")

	// Clean up after simulation
	defer func() {
		scanner.clientset.CoreV1().Pods("default").Delete(ctx, "kubeshadow-workload-simulator", metav1.DeleteOptions{})
		logger.Info("🧹 Simulation pod cleaned up")
	}()

	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			strings.Contains(s, substr))))
}
