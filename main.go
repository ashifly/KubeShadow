package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"
	// Import specific module sub-packages
	cluster_exploit "kubeshadow/modules/cluster_exploit"
	dashboard_cmd "kubeshadow/modules/dashboard"
	data_exfil "kubeshadow/modules/data_exfil"
	demo "kubeshadow/modules/demo"
	exploitation "kubeshadow/modules/exploitation"
	lab "kubeshadow/modules/lab"
	multi_cloud "kubeshadow/modules/multi_cloud"
	out_cluster "kubeshadow/modules/out_cluster"
	owasp_top10 "kubeshadow/modules/owasp_top10"
	recon "kubeshadow/modules/recon"
	stealth "kubeshadow/modules/stealth"
	recon_graph "kubeshadow/pkg/recon_graph"

	// Note: ai_engine package is not yet exposed as commands

	"kubeshadow/pkg/banner"
	"kubeshadow/pkg/dashboard"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubeshadow",
	Short: "KubeShadow - Kubernetes Security Testing Tool",
	Long:  "A Kubernetes security testing tool for analyzing and exploiting cluster security misconfigurations",
	Run: func(cmd *cobra.Command, args []string) {
		// Print the banner when the root command is run without arguments
		banner.Print()
		// Then show the help message
		cmd.Help()
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Show banner for help and main commands
		if cmd.Name() == "help" || cmd.Name() == "kubeshadow" {
			banner.Print()
		}

		// Start dashboard if requested
		dashboardFlag, _ := cmd.Flags().GetBool("dashboard")
		dashboardPort, _ := cmd.Flags().GetInt("dashboard-port")

		if dashboardFlag {
			if err := dashboard.StartDashboardIfRequested(dashboardFlag, dashboardPort); err != nil {
				fmt.Printf("Failed to start dashboard: %v\n", err)
			} else {
				fmt.Printf("🚀 Enhanced Dashboard started with attack-map visualization\n")
			}
		}
	},
}

func init() {
	// Add global flags for dashboard functionality
	rootCmd.PersistentFlags().Bool("dashboard", false, "Enable dashboard to display command results on web interface")
	rootCmd.PersistentFlags().Int("dashboard-port", 8080, "Port for the dashboard web server")

	// Add commands in logical workflow order with proper grouping

	// 1. LAB SETUP (First - create environment)
	rootCmd.AddCommand(dashboard.WrapCommand("lab", lab.LabCmd))
	rootCmd.AddCommand(dashboard_cmd.DashboardCmd)

	// 2. RECONNAISSANCE (Discover vulnerabilities)
	rootCmd.AddCommand(dashboard.WrapCommand("recon", recon.ReconCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("owasp", owasp_top10.OwaspCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("recon-graph", recon_graph.ReconGraphCmd))

	// 3. EXPLOITATION (Attack what you found)
	rootCmd.AddCommand(dashboard.WrapCommand("exploitation", exploitation.ExploitationCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("rbac-escalate", cluster_exploit.RBACEscalateCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("sidecar-inject", cluster_exploit.SidecarInjectCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("kubelet-jack", cluster_exploit.KubeletJackerCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("etcd-inject", cluster_exploit.EtcdInjectCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("namespace-pivot", cluster_exploit.NamespacePivotCmd))

	// 4. CLOUD EXPLOITATION (Cloud-specific attacks)
	rootCmd.AddCommand(dashboard.WrapCommand("metadata-hijack", multi_cloud.MetadataHijackCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("cloud-elevator", multi_cloud.CloudElevatorCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("assume-role-abuse", multi_cloud.AssumeRoleAbuseCmd))

	// 5. POST-EXPLOITATION (Persistence, data exfil, cleanup)
	rootCmd.AddCommand(dashboard.WrapCommand("data-exfil", data_exfil.DataExfilCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("registry-backdoor", out_cluster.RegistryBackdoorCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("audit-bypass", stealth.AuditBypassCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("dns-cache-poison", stealth.DNSCachePoisonCmd))
	rootCmd.AddCommand(dashboard.WrapCommand("cleanup", stealth.CleanupCmd))

	// 6. UTILITIES (Demo and other tools)
	rootCmd.AddCommand(dashboard.WrapCommand("demo", demo.DemoCmd))

	// Override the help command to show logical order
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Println("A Kubernetes security testing tool for analyzing and exploiting cluster security misconfigurations")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Printf("  %s [flags]\n", cmd.CommandPath())
		fmt.Printf("  %s [command]\n", cmd.CommandPath())
		fmt.Println("")
		fmt.Println("Available Commands:")
		fmt.Println("")
		fmt.Println("🔧 LAB SETUP:")
		fmt.Println("  lab               Deploy KubeShadow lab environment for security testing")
		fmt.Println("  dashboard         Start the KubeShadow web dashboard")
		fmt.Println("")
		fmt.Println("🔍 RECONNAISSANCE:")
		fmt.Println("  recon             Perform comprehensive cluster, cloud, and system reconnaissance")
		fmt.Println("  owasp             OWASP Top 10 for Kubernetes Security")
		fmt.Println("  recon-graph       Recon Graph and Attack Chain Analysis")
		fmt.Println("")
		fmt.Println("🎯 EXPLOITATION:")
		fmt.Println("  exploitation      KubeShadow Exploitation Framework - Metasploit-style modules")
		fmt.Println("  rbac-escalate     Attempt to escalate privileges using RBAC misconfigurations")
		fmt.Println("  sidecar-inject    Inject a malicious sidecar container into a pod")
		fmt.Println("  kubeletjacker     Exploit misconfigured or open kubelet APIs for pod access, logs, and potential RCE")
		fmt.Println("  etcdinject        Inject a pod directly via etcd (dangerous)")
		fmt.Println("  namespace-pivot   Analyze namespace isolation and pivot opportunities")
		fmt.Println("")
		fmt.Println("☁️  CLOUD EXPLOITATION:")
		fmt.Println("  metadata-hijack   Attempt to hijack cloud metadata service credentials")
		fmt.Println("  cloud-elevator   Attempt to elevate privileges in cloud environments")
		fmt.Println("  assume-role-abuse Attempt to assume an AWS IAM role")
		fmt.Println("")
		fmt.Println("🔄 POST-EXPLOITATION:")
		fmt.Println("  data-exfil        Exfiltrate data to cloud storage using presigned URLs")
		fmt.Println("  registry-backdoor Inject a backdoor into a Docker image and push it")
		fmt.Println("  audit-bypass      Analyze and test Kubernetes audit policy bypasses")
		fmt.Println("  dns-poison        Test for DNS cache poisoning vulnerabilities")
		fmt.Println("  cleanup           Clean up artifacts from penetration testing activities")
		fmt.Println("")
		fmt.Println("🛠️  UTILITIES:")
		fmt.Println("  demo              Demo command to test dashboard functionality")
		fmt.Println("  help              Help about any command")
		fmt.Println("")
		fmt.Println("Flags:")
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			if flag.Hidden {
				return
			}
			fmt.Printf("      --%-15s %s\n", flag.Name, flag.Usage)
		})
		fmt.Println("")
		fmt.Printf("Use \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
	})

	// Enable dashboard integration for all modules
	enableDashboardIntegration(rootCmd)

	// Since the root command's Run function now explicitly prints help,
	// we might remove the default help command printing from Cobra.
	// rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
}

func main() {
	// Set up graceful shutdown for dashboard
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\nShutting down dashboard...")
		dashboard.GetInstance().Stop()
		os.Exit(0)
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// enableDashboardIntegration enables dashboard integration for all commands
func enableDashboardIntegration(rootCmd *cobra.Command) {
	// Recursively enable dashboard for all subcommands
	enableDashboardForCommand(rootCmd)
}

// enableDashboardForCommand enables dashboard integration for a command and its subcommands
func enableDashboardForCommand(cmd *cobra.Command) {
	// Add dashboard flag to this command if it doesn't have one
	if !cmd.Flags().Changed("dashboard") {
		cmd.Flags().Bool("dashboard", false, "Enable dashboard to display results")
	}

	// Enable dashboard integration for this command
	dashboard.EnableDashboardForModule(getModuleName(cmd), cmd)

	// Recursively enable for all subcommands
	for _, subCmd := range cmd.Commands() {
		enableDashboardForCommand(subCmd)
	}
}

// getModuleName determines the module name from the command
func getModuleName(cmd *cobra.Command) string {
	// Map command names to module names
	moduleMap := map[string]string{
		"recon":             "recon",
		"etcd-inject":       "cluster-exploit",
		"kubelet-hijack":    "cluster-exploit",
		"sidecar-inject":    "cluster-exploit",
		"rbac-escalate":     "cluster-exploit",
		"namespace-pivot":   "cluster-exploit",
		"metadata-hijack":   "multi-cloud",
		"cloud-elevator":    "multi-cloud",
		"assume-role":       "multi-cloud",
		"audit-bypass":      "stealth",
		"dns-poison":        "stealth",
		"cleanup":           "stealth",
		"registry-backdoor": "out-cluster",
		"dashboard":         "dashboard",
		"demo":              "demo",
		"data-exfil":        "data-exfil",
		"lab":               "lab",
		"owasp":             "owasp-top10",
		"k01":               "k01-insecure-workload",
		"k02":               "k02-supply-chain",
		"k03":               "k03-rbac",
		"k04":               "k04-policy",
		"exploitation":      "exploitation",
		"payloads":          "exploitation",
		"exploits":          "exploitation",
		"persistence":       "exploitation",
		"post-ex":           "exploitation",
		"evasion":           "exploitation",
	}

	if module, exists := moduleMap[cmd.Name()]; exists {
		return module
	}

	// Default to command name
	return cmd.Name()
}
