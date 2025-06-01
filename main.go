package main

import (
	"fmt"
	"os"

	// Import specific module sub-packages
	cluster_exploit "kubeshadow/modules/cluster_exploit"
	multi_cloud "kubeshadow/modules/multi_cloud"
	out_cluster "kubeshadow/modules/out_cluster"
	recon "kubeshadow/modules/recon"
	stealth "kubeshadow/modules/stealth"

	// Note: ai_engine package is not yet exposed as commands

	"kubeshadow/pkg/banner"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubeshadow",
	Short: "KubeShadow - Kubernetes Security Testing Tool",
	Long:  "A Kubernetes security testing tool for analyzing and exploiting cluster security misconfigurations",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// This PersistentPreRun logic is for actions *before* any command runs (including subcommands).
		// It's currently set up to *not* print the banner for 'help' or 'completion'.
		// The banner for the root command itself when run with no args is handled in the Run function below.
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Print the banner when the root command is run without arguments
		banner.Print()
		// Then show the help message
		cmd.Help()
	},
}

func init() {
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

	// Since the root command's Run function now explicitly prints help,
	// we might remove the default help command printing from Cobra.
	// rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
