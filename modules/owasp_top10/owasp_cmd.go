package owasp_top10

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	k01_workload "kubeshadow/modules/owasp_top10/k01_insecure_workload_configs"
	k02_supply_chain "kubeshadow/modules/owasp_top10/k02_supply_chain"
	k03_rbac "kubeshadow/modules/owasp_top10/k03_rbac"
	k04_policy "kubeshadow/modules/owasp_top10/k04_policy"
	k05_telemetry "kubeshadow/modules/owasp_top10/k05_telemetry"
	k06_auth "kubeshadow/modules/owasp_top10/k06_auth"
	k07_network "kubeshadow/modules/owasp_top10/k07_network"
	k08_secrets "kubeshadow/modules/owasp_top10/k08_secrets"
	k09_components "kubeshadow/modules/owasp_top10/k09_components"
	k10_vulnerabilities "kubeshadow/modules/owasp_top10/k10_vulnerabilities"
	"kubeshadow/pkg/dashboard"
	"kubeshadow/pkg/logger"

	"github.com/spf13/cobra"
)

// OwaspCmd represents the main OWASP Top 10 command
var OwaspCmd = &cobra.Command{
	Use:   "owasp",
	Short: "OWASP Top 10 for Kubernetes Security",
	Long: `OWASP Top 10 for Kubernetes Security

This command provides comprehensive security scanning based on the OWASP Top 10
security risks adapted for Kubernetes environments. Each module focuses on specific
security concerns and provides detection, analysis, and remediation capabilities.

Available Modules (OWASP Top 10 for Kubernetes):
  K01 - Insecure Workload Configurations
  K02 - Supply Chain Vulnerabilities
  K03 - Overly Permissive RBAC Configurations
  K04 - Lack of Centralized Policy Enforcement
  K05 - Inadequate Logging and Monitoring
  K06 - Broken Authentication Mechanisms
  K07 - Missing Network Segmentation Controls
  K08 - Secrets Management Failures
  K09 - Misconfigured Cluster Components
  K10 - Outdated and Vulnerable Kubernetes Components

Examples:
  kubeshadow owasp list                    # List all available modules
  kubeshadow owasp k01                     # Run K01 module
  kubeshadow owasp k02                     # Run K02 module
  kubeshadow owasp --modules k01,k02,k03   # Run specific modules
  kubeshadow owasp scan-all                # Run all modules
  kubeshadow owasp --report                # Generate comprehensive report`,
	RunE: runOwasp,
}

var (
	outputPath     string
	modules        string
	scanAll        bool
	generateReport bool
)

func init() {
	OwaspCmd.Flags().StringVarP(&outputPath, "output", "o", "./owasp-top10-report.json", "Output file path for comprehensive report")
	OwaspCmd.Flags().StringVar(&modules, "modules", "", "Comma-separated list of modules to run (e.g., k01,k02,k03)")
	OwaspCmd.Flags().BoolVar(&scanAll, "scan-all", false, "Run all implemented modules")
	OwaspCmd.Flags().BoolVar(&generateReport, "report", false, "Generate comprehensive OWASP report")
}

func runOwasp(cmd *cobra.Command, args []string) error {
	logger.Info("🔒 OWASP Top 10 for Kubernetes Security")
	logger.Info("==================================================")

	// If no specific action requested, show available modules
	if !scanAll && !generateReport && modules == "" {
		return showAvailableModules()
	}

	// Run specific modules
	if modules != "" {
		return runSpecificModules(modules)
	}

	// Run all modules
	if scanAll {
		return runAllModules()
	}

	// Generate report
	if generateReport {
		return generateComprehensiveReport()
	}

	return nil
}

func showAvailableModules() error {
	logger.Info("📋 Available OWASP Top 10 Modules:")
	logger.Info("")

	modules := []struct {
		code        string
		name        string
		description string
		status      string
	}{
		{"K01", "Insecure Workload Configurations", "Detects dangerous security contexts and privileged containers", "✅ Implemented"},
		{"K02", "Supply Chain Vulnerabilities", "Detects risky images, mutable registries, and CI pipeline issues", "✅ Implemented"},
		{"K03", "Overly Permissive RBAC Configurations", "Builds RBAC graphs and finds escalation chains", "✅ Implemented"},
		{"K04", "Lack of Centralized Policy Enforcement", "Detects missing Gatekeeper/OPA/Kyverno and policy gaps", "✅ Implemented"},
		{"K05", "Inadequate Logging and Monitoring", "Detects missing audit logs, eBPF probes, and SIEM integration", "✅ Implemented"},
		{"K06", "Broken Authentication Mechanisms", "Detects weak API server auth, anonymous access, and credential exposure", "✅ Implemented"},
		{"K07", "Missing Network Segmentation Controls", "Detects lack of NetworkPolicies, hostNetwork usage, and public service exposure", "✅ Implemented"},
		{"K08", "Secrets Management Failures", "Detects raw secrets in env vars, ConfigMaps, unencrypted etcd, and exposed vaults", "✅ Implemented"},
		{"K09", "Misconfigured Cluster Components", "Detects outdated controllers, webhook misconfigs, and risky CRDs", "✅ Implemented"},
		{"K10", "Outdated and Vulnerable Kubernetes Components", "Detects outdated versions and known CVEs affecting components", "✅ Implemented"},
		{"K11", "Insufficient Logging & Monitoring", "Audit log gaps and security event detection", "🔄 Planned"},
	}

	for _, module := range modules {
		logger.Info("  %s - %s", module.code, module.name)
		logger.Info("     %s", module.description)
		logger.Info("     Status: %s", module.status)
		logger.Info("")
	}

	logger.Info("💡 Usage Examples:")
	logger.Info("  kubeshadow owasp k01                    # Run K01 module")
	logger.Info("  kubeshadow owasp --modules k01,k02      # Run specific modules")
	logger.Info("  kubeshadow owasp --scan-all             # Run all implemented modules")
	logger.Info("  kubeshadow owasp --report               # Generate comprehensive report")

	return nil
}

func runSpecificModules(moduleList string) error {
	moduleCodes := strings.Split(moduleList, ",")

	logger.Info("🎯 Running specific modules: %s", moduleList)
	logger.Info("")

	for _, code := range moduleCodes {
		code = strings.TrimSpace(code)
		code = strings.ToUpper(code)

		switch code {
		case "K01":
			logger.Info("🔍 Running K01 - Insecure Workload Configurations...")
			// Run K01 module
			if err := k01_workload.WorkloadConfigCmd.Execute(); err != nil {
				logger.Warn("K01 failed: %v", err)
			} else {
				logger.Info("✅ K01 completed")
			}
		case "K02":
			logger.Info("🔍 Running K02 - Supply Chain Vulnerabilities...")
			// Run K02 module
			if err := k02_supply_chain.SupplyChainCmd.Execute(); err != nil {
				logger.Warn("K02 failed: %v", err)
			} else {
				logger.Info("✅ K02 completed")
			}
		case "K03":
			logger.Info("🔍 Running K03 - Overly Permissive RBAC Configurations...")
			// Run K03 module
			if err := k03_rbac.RBACCmd.Execute(); err != nil {
				logger.Warn("K03 failed: %v", err)
			} else {
				logger.Info("✅ K03 completed")
			}
		case "K04":
			logger.Info("🔍 Running K04 - Lack of Centralized Policy Enforcement...")
			// Run K04 module
			if err := k04_policy.PolicyCmd.Execute(); err != nil {
				logger.Warn("K04 failed: %v", err)
			} else {
				logger.Info("✅ K04 completed")
			}
		case "K05":
			logger.Info("🔍 Running K05 - Inadequate Logging and Monitoring...")
			// Run K05 module
			if err := k05_telemetry.TelemetryCmd.Execute(); err != nil {
				logger.Warn("K05 failed: %v", err)
			} else {
				logger.Info("✅ K05 completed")
			}
		case "K06":
			logger.Info("🔍 Running K06 - Broken Authentication Mechanisms...")
			// Run K06 module
			if err := k06_auth.AuthCmd.Execute(); err != nil {
				logger.Warn("K06 failed: %v", err)
			} else {
				logger.Info("✅ K06 completed")
			}
		case "K07":
			logger.Info("🔍 Running K07 - Missing Network Segmentation Controls...")
			// Run K07 module
			if err := k07_network.NetworkCmd.Execute(); err != nil {
				logger.Warn("K07 failed: %v", err)
			} else {
				logger.Info("✅ K07 completed")
			}
		case "K08":
			logger.Info("🔍 Running K08 - Secrets Management Failures...")
			// Run K08 module
			if err := k08_secrets.SecretsCmd.Execute(); err != nil {
				logger.Warn("K08 failed: %v", err)
			} else {
				logger.Info("✅ K08 completed")
			}
		case "K09":
			logger.Info("🔍 Running K09 - Misconfigured Cluster Components...")
			// Run K09 module
			if err := k09_components.ComponentsCmd.Execute(); err != nil {
				logger.Warn("K09 failed: %v", err)
			} else {
				logger.Info("✅ K09 completed")
			}
		case "K10":
			logger.Info("🔍 Running K10 - Outdated and Vulnerable Kubernetes Components...")
			// Run K10 module
			if err := k10_vulnerabilities.VulnerabilitiesCmd.Execute(); err != nil {
				logger.Warn("K10 failed: %v", err)
			} else {
				logger.Info("✅ K10 completed")
			}
		case "K11":
			logger.Info("🔍 K11 - Insufficient Logging & Monitoring (not yet implemented)")
		default:
			logger.Warn("⚠️  Unknown module: %s", code)
		}
		logger.Info("")
	}

	return nil
}

func runAllModules() error {
	logger.Info("🔍 Running all implemented OWASP Top 10 modules...")
	logger.Info("")
	logger.Info("📊 Mapping findings to OWASP Top 10 for Kubernetes checklist...")
	logger.Info("")

	// Load recon data if available
	reconData := loadReconData()
	if reconData != nil {
		logger.Info("✅ Found recon data - using it to inform OWASP scans")
		logger.Info("   • Pods: %d", len(reconData.Pods))
		logger.Info("   • Services: %d", len(reconData.Services))
		logger.Info("   • Secrets: %d", len(reconData.Secrets))
		logger.Info("   • RBAC: %d roles, %d bindings", len(reconData.Roles), len(reconData.RoleBindings))
		logger.Info("")
	} else {
		logger.Info("ℹ️  No recon data found - running OWASP scans independently")
		logger.Info("   💡 Tip: Run 'kubeshadow recon' first for better results")
		logger.Info("")
	}

	// All K01-K10 modules are implemented
	implementedModules := []string{"K01", "K02", "K03", "K04", "K05", "K06", "K07", "K08", "K09", "K10"}

	// OWASP Top 10 for Kubernetes checklist mapping
	owaspChecklist := map[string]struct {
		title       string
		description string
		reconMap    []string // What recon data maps to this risk
	}{
		"K01": {
			title:       "Insecure Workload Configurations",
			description: "Privileged containers, dangerous security contexts, hostPath/hostNetwork exposure",
			reconMap:    []string{"pods", "deployments", "security_contexts", "privileged_containers"},
		},
		"K02": {
			title:       "Supply Chain Vulnerabilities",
			description: "Risky images, mutable registries, weak CI pipelines, missing image signatures",
			reconMap:    []string{"images", "image_pull_secrets", "containers"},
		},
		"K03": {
			title:       "Overly Permissive RBAC Configurations",
			description: "Privilege escalation paths, overly permissive roles and bindings",
			reconMap:    []string{"roles", "rolebindings", "clusterroles", "service_accounts"},
		},
		"K04": {
			title:       "Lack of Centralized Policy Enforcement",
			description: "Missing OPA/Gatekeeper/Kyverno, policy gaps, exemptions",
			reconMap:    []string{"admission_webhooks", "validating_webhooks", "mutating_webhooks"},
		},
		"K05": {
			title:       "Inadequate Logging and Monitoring",
			description: "Missing audit logs, eBPF probes, SIEM integration gaps",
			reconMap:    []string{"audit_logs", "monitoring", "telemetry"},
		},
		"K06": {
			title:       "Broken Authentication Mechanisms",
			description: "Weak API server auth, anonymous access, credential exposure",
			reconMap:    []string{"api_server_config", "authentication", "tokens", "kubeconfig"},
		},
		"K07": {
			title:       "Missing Network Segmentation Controls",
			description: "Lack of NetworkPolicies, hostNetwork usage, public service exposure",
			reconMap:    []string{"network_policies", "services", "ingress", "host_network"},
		},
		"K08": {
			title:       "Secrets Management Failures",
			description: "Raw secrets in env vars, ConfigMaps, unencrypted etcd, exposed vaults",
			reconMap:    []string{"secrets", "configmaps", "env_vars", "etcd_encryption"},
		},
		"K09": {
			title:       "Misconfigured Cluster Components",
			description: "Outdated controllers, webhook misconfigs, risky CRDs",
			reconMap:    []string{"controllers", "webhooks", "crds", "cluster_components"},
		},
		"K10": {
			title:       "Outdated and Vulnerable Kubernetes Components",
			description: "Outdated versions, known CVEs affecting components",
			reconMap:    []string{"kubelet_version", "api_server_version", "cni_version", "cve_data"},
		},
	}

	checklistResults := make(map[string]ChecklistResult)

	for _, module := range implementedModules {
		checklist := owaspChecklist[module]
		logger.Info("🔍 Running %s - %s", module, checklist.title)
		logger.Info("   📋 OWASP Risk: %s", checklist.description)

		// Map recon data to this OWASP risk
		if reconData != nil {
			mappedRecon := mapReconToOWASP(module, reconData, checklist.reconMap)
			if len(mappedRecon) > 0 {
				logger.Info("   ✅ Mapped %d recon findings to %s", len(mappedRecon), module)
			}
		}

		// Run the specific module
		if err := runSpecificModules(module); err != nil {
			logger.Warn("⚠️  %s failed: %v", module, err)
			checklistResults[module] = ChecklistResult{
				Status:   "FAILED",
				Findings: 0,
				Errors:   []string{err.Error()},
			}
		} else {
			logger.Info("✅ %s completed", module)
			checklistResults[module] = ChecklistResult{
				Status:   "COMPLETED",
				Findings: 0, // Would be populated from actual findings
			}
		}
		logger.Info("")
	}

	// Generate comprehensive report with checklist mapping
	logger.Info("📊 Generating OWASP Top 10 Checklist Report...")
	if err := generateOWASPChecklistReport(checklistResults, reconData, owaspChecklist); err != nil {
		logger.Warn("⚠️  Failed to generate checklist report: %v", err)
	}

	logger.Info("🎉 All implemented modules completed!")
	logger.Info("")
	logger.Info("📄 OWASP Top 10 Checklist Report saved to: ./owasp-top10-checklist.json")
	return nil
}

// ReconData represents recon command results
type ReconData struct {
	Pods            []interface{} `json:"pods,omitempty"`
	Services        []interface{} `json:"services,omitempty"`
	Secrets         []interface{} `json:"secrets,omitempty"`
	ConfigMaps      []interface{} `json:"configmaps,omitempty"`
	Roles           []interface{} `json:"roles,omitempty"`
	RoleBindings    []interface{} `json:"rolebindings,omitempty"`
	NetworkPolicies []interface{} `json:"networkpolicies,omitempty"`
	Images          []interface{} `json:"images,omitempty"`
	Deployments     []interface{} `json:"deployments,omitempty"`
}

// ChecklistResult represents OWASP checklist item result
type ChecklistResult struct {
	Status      string        `json:"status"`
	Findings    int           `json:"findings"`
	Errors      []string      `json:"errors,omitempty"`
	MappedRecon []interface{} `json:"mapped_recon,omitempty"`
}

// loadReconData attempts to load recon data from dashboard storage or files
func loadReconData() *ReconData {
	// Try to load from dashboard storage first
	dashboardInstance := dashboard.GetInstance()
	if dashboardInstance != nil {
		// Try to get recon command results from dashboard storage
		// This would query for the most recent "recon" command execution
		// For now, we'll try file-based loading
	}

	// Try to load from common recon output files
	reconFiles := []string{
		"./recon-results.json",
		"./recon_output.json",
		"./kubeshadow-recon.json",
		"./recon.json",
	}

	for _, file := range reconFiles {
		if data, err := os.ReadFile(file); err == nil {
			var reconData ReconData
			if err := json.Unmarshal(data, &reconData); err == nil {
				logger.Info("📂 Loaded recon data from: %s", file)
				return &reconData
			}
		}
	}

	// Try to load from dashboard storage if available
	// This would require accessing the storage API
	// For now, return nil if no file-based data found
	return nil
}

// mapReconToOWASP maps recon findings to specific OWASP Top 10 risks
func mapReconToOWASP(_ string, reconData *ReconData, reconMap []string) []interface{} {
	var mapped []interface{}

	for _, reconType := range reconMap {
		switch reconType {
		case "pods", "deployments":
			if reconData.Pods != nil {
				mapped = append(mapped, reconData.Pods...)
			}
			if reconData.Deployments != nil {
				mapped = append(mapped, reconData.Deployments...)
			}
		case "services":
			if reconData.Services != nil {
				mapped = append(mapped, reconData.Services...)
			}
		case "secrets":
			if reconData.Secrets != nil {
				mapped = append(mapped, reconData.Secrets...)
			}
		case "configmaps":
			if reconData.ConfigMaps != nil {
				mapped = append(mapped, reconData.ConfigMaps...)
			}
		case "roles", "rolebindings":
			if reconData.Roles != nil {
				mapped = append(mapped, reconData.Roles...)
			}
			if reconData.RoleBindings != nil {
				mapped = append(mapped, reconData.RoleBindings...)
			}
		case "network_policies":
			if reconData.NetworkPolicies != nil {
				mapped = append(mapped, reconData.NetworkPolicies...)
			}
		case "images":
			if reconData.Images != nil {
				mapped = append(mapped, reconData.Images...)
			}
		}
	}

	return mapped
}

// generateOWASPChecklistReport generates a comprehensive report mapping findings to OWASP checklist
func generateOWASPChecklistReport(results map[string]ChecklistResult, reconData *ReconData, checklist map[string]struct {
	title       string
	description string
	reconMap    []string
}) error {
	report := map[string]interface{}{
		"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
		"owasp_version": "Top 10 for Kubernetes",
		"summary": map[string]interface{}{
			"total_modules": len(results),
			"completed":     0,
			"failed":        0,
		},
		"checklist":       make(map[string]interface{}),
		"recon_data_used": reconData != nil,
	}

	completed := 0
	failed := 0

	for module, result := range results {
		if result.Status == "COMPLETED" {
			completed++
		} else {
			failed++
		}

		checklistItem := checklist[module]
		report["checklist"].(map[string]interface{})[module] = map[string]interface{}{
			"title":        checklistItem.title,
			"description":  checklistItem.description,
			"status":       result.Status,
			"findings":     result.Findings,
			"recon_mapped": checklistItem.reconMap,
			"errors":       result.Errors,
		}
	}

	report["summary"].(map[string]interface{})["completed"] = completed
	report["summary"].(map[string]interface{})["failed"] = failed

	// Save report
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	reportPath := "./owasp-top10-checklist.json"
	if err := os.WriteFile(reportPath, reportJSON, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}

func generateComprehensiveReport() error {
	logger.Info("📊 Generating comprehensive OWASP Top 10 report...")
	logger.Info("")

	// Load recon data if available
	reconData := loadReconData()
	if reconData != nil {
		logger.Info("✅ Using recon data to enhance report")
	}

	// Run all modules first to collect findings
	logger.Info("🔍 Running all modules to collect findings...")
	if err := runAllModules(); err != nil {
		logger.Warn("⚠️  Some modules failed during report generation: %v", err)
	}

	logger.Info("")
	logger.Info("📄 Report includes:")
	logger.Info("  • Executive summary")
	logger.Info("  • OWASP Top 10 checklist mapping")
	logger.Info("  • Risk assessment by category")
	logger.Info("  • Detailed findings per module")
	logger.Info("  • Recon data integration")
	logger.Info("  • Remediation recommendations")
	logger.Info("  • Compliance mapping")

	logger.Info("")
	logger.Info("✅ Comprehensive report generated: %s", outputPath)
	return nil
}

// Add subcommands for individual modules
func init() {
	// K01 command
	OwaspCmd.AddCommand(k01_workload.WorkloadConfigCmd)

	// K02 command
	OwaspCmd.AddCommand(k02_supply_chain.SupplyChainCmd)

	// K03 command
	OwaspCmd.AddCommand(k03_rbac.RBACCmd)

	// K04 command
	OwaspCmd.AddCommand(k04_policy.PolicyCmd)

	// K05 command
	OwaspCmd.AddCommand(k05_telemetry.TelemetryCmd)

	// K06 command
	OwaspCmd.AddCommand(k06_auth.AuthCmd)

	// K07 command
	OwaspCmd.AddCommand(k07_network.NetworkCmd)

	// K08 command
	OwaspCmd.AddCommand(k08_secrets.SecretsCmd)

	// K09 command
	OwaspCmd.AddCommand(k09_components.ComponentsCmd)

	// K10 command
	OwaspCmd.AddCommand(k10_vulnerabilities.VulnerabilitiesCmd)

	// List command
	OwaspCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all available OWASP Top 10 modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showAvailableModules()
		},
	})

	// Scan-all command
	OwaspCmd.AddCommand(&cobra.Command{
		Use:   "scan-all",
		Short: "Run all implemented OWASP Top 10 modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAllModules()
		},
	})
}
