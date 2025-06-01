package main

import (
	"fmt"
	"os"

	"kubeshadow/modules"
	"kubeshadow/pkg/banner"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubeshadow",
	Short: "KubeShadow - Kubernetes Security Testing Tool",
	Long:  "A Kubernetes security testing tool for analyzing and exploiting cluster security misconfigurations",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Show banner for all commands except help and completion
		if cmd.Name() != "help" && cmd.Name() != "completion" && cmd.Parent().Name() != "completion" {
			banner.Print()
			if cmd.Name() != "kubeshadow" {
				banner.PrintModule(cmd.Name())
			}
		}
	},
}

func init() {
	// Add all available commands
	rootCmd.AddCommand(modules.EtcdInjectCmd)
	rootCmd.AddCommand(modules.KubeletJackerCmd)
	rootCmd.AddCommand(modules.ReconCmd)
	rootCmd.AddCommand(modules.SidecarInjectCmd)
	rootCmd.AddCommand(modules.MetadataHijackCmd)
	rootCmd.AddCommand(modules.CloudElevatorCmd)
	rootCmd.AddCommand(modules.RBACEscalateCmd)
	rootCmd.AddCommand(modules.AuditBypassCmd)
	rootCmd.AddCommand(modules.DNSCachePoisonCmd)
	rootCmd.AddCommand(modules.NamespacePivotCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
