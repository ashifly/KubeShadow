package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	// Import specific module sub-packages
	cluster_exploit "kubeshadow/modules/cluster_exploit"
	dashboard_cmd "kubeshadow/modules/dashboard"
	data_exfil "kubeshadow/modules/data_exfil"
	demo "kubeshadow/modules/demo"
	lab "kubeshadow/modules/lab"
	multi_cloud "kubeshadow/modules/multi_cloud"
	out_cluster "kubeshadow/modules/out_cluster"
	recon "kubeshadow/modules/recon"
	stealth "kubeshadow/modules/stealth"

	// Note: ai_engine package is not yet exposed as commands

	"kubeshadow/pkg/banner"
	"kubeshadow/pkg/dashboard"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubeshadow",
	Short: "KubeShadow - Kubernetes Security Testing Tool",
	Long:  "A Kubernetes security testing tool for analyzing and exploiting cluster security misconfigurations",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Start dashboard if requested
		dashboardFlag, _ := cmd.Flags().GetBool("dashboard")
		dashboardPort, _ := cmd.Flags().GetInt("dashboard-port")

		if dashboardFlag {
			if err := dashboard.StartDashboardIfRequested(dashboardFlag, dashboardPort); err != nil {
				fmt.Printf("Failed to start dashboard: %v\n", err)
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Print the banner when the root command is run without arguments
		banner.Print()
		// Then show the help message
		cmd.Help()
	},
}

func init() {
	// Add global flags for dashboard functionality
	rootCmd.PersistentFlags().Bool("dashboard", false, "Enable dashboard to display command results on web interface")
	rootCmd.PersistentFlags().Int("dashboard-port", 8080, "Port for the dashboard web server")

	// Add all available commands from their new packages
	rootCmd.AddCommand(cluster_exploit.EtcdInjectCmd)
	rootCmd.AddCommand(cluster_exploit.KubeletJackerCmd)
	rootCmd.AddCommand(recon.ReconCmd)
	rootCmd.AddCommand(cluster_exploit.SidecarInjectCmd)
	rootCmd.AddCommand(multi_cloud.MetadataHijackCmd)
	rootCmd.AddCommand(multi_cloud.CloudElevatorCmd)
	rootCmd.AddCommand(multi_cloud.AssumeRoleAbuseCmd)
	rootCmd.AddCommand(cluster_exploit.RBACEscalateCmd)
	rootCmd.AddCommand(stealth.AuditBypassCmd)
	rootCmd.AddCommand(stealth.DNSCachePoisonCmd)
	rootCmd.AddCommand(stealth.CleanupCmd)
	rootCmd.AddCommand(cluster_exploit.NamespacePivotCmd)
	rootCmd.AddCommand(out_cluster.RegistryBackdoorCmd)
	rootCmd.AddCommand(dashboard_cmd.DashboardCmd)
	rootCmd.AddCommand(demo.DemoCmd)
	rootCmd.AddCommand(data_exfil.DataExfilCmd)
	rootCmd.AddCommand(lab.LabCmd)

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
