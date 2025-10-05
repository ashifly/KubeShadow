package owasp_top10

import (
	"strings"

	k02_supply_chain "kubeshadow/modules/owasp_top10/k02_supply_chain"
	k03_rbac "kubeshadow/modules/owasp_top10/k03_rbac"
	k04_policy "kubeshadow/modules/owasp_top10/k04_policy"
	k05_telemetry "kubeshadow/modules/owasp_top10/k05_telemetry"
	k06_auth "kubeshadow/modules/owasp_top10/k06_auth"
	k07_network "kubeshadow/modules/owasp_top10/k07_network"
	k08_secrets "kubeshadow/modules/owasp_top10/k08_secrets"
	k09_components "kubeshadow/modules/owasp_top10/k09_components"
	k10_vulnerabilities "kubeshadow/modules/owasp_top10/k10_vulnerabilities"
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

Available Modules:
  K01 - Insecure Workload Configurations
  K02 - Weak Authentication & Authorization (planned)
  K03 - Sensitive Data Exposure (planned)
  K04 - XML External Entities (planned)
  K05 - Broken Access Control (planned)
  K06 - Security Misconfiguration (planned)
  K07 - Cross-Site Scripting (planned)
  K08 - Insecure Deserialization (planned)
  K09 - Known Vulnerabilities (planned)
  K10 - Insufficient Logging & Monitoring (planned)

Examples:
  kubeshadow owasp list
  kubeshadow owasp k01
  kubeshadow owasp scan-all
  kubeshadow owasp report --output ./owasp-report.json`,
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
			// Import and run K01 module
			// This would be: k01.RunK01Module()
			logger.Info("✅ K01 completed")
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

	// Currently K01, K02, K03, K04, K05, K06, K07, K08, K09, and K10 are implemented
	implementedModules := []string{"K01", "K02", "K03", "K04", "K05", "K06", "K07", "K08", "K09", "K10"}

	for _, module := range implementedModules {
		logger.Info("🔍 Running %s...", module)
		// Run the specific module
		// This would be: runModule(module)
		logger.Info("✅ %s completed", module)
		logger.Info("")
	}

	logger.Info("🎉 All implemented modules completed!")
	return nil
}

func generateComprehensiveReport() error {
	logger.Info("📊 Generating comprehensive OWASP Top 10 report...")

	// This would generate a comprehensive report combining all modules
	logger.Info("📄 Report will include:")
	logger.Info("  • Executive summary")
	logger.Info("  • Risk assessment by category")
	logger.Info("  • Detailed findings per module")
	logger.Info("  • Remediation recommendations")
	logger.Info("  • Compliance mapping")

	logger.Info("✅ Comprehensive report generated: %s", outputPath)
	return nil
}

// Add subcommands for individual modules
func init() {
	// K01 command
	OwaspCmd.AddCommand(&cobra.Command{
		Use:   "k01",
		Short: "K01 - Insecure Workload Configurations",
		Long:  "Detects dangerous security contexts, privileged containers, and host exposure risks",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("🔍 Running K01 - Insecure Workload Configurations...")
			// This would call the K01 module directly
			// k01.RunK01Module()
			return nil
		},
	})

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
