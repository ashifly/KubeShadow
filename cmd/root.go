package cmd

import (
	"fmt"
	"os"

	"kubeshadow/modules"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubeshadow",
	Short: "KubeShadow - Kubernetes offensive security tool",
	Long: `KubeShadow is a Kubernetes offensive security tool designed for red team operations.
It provides capabilities for reconnaissance, pod injection, and exploitation of misconfigured components.`,
}

// Execute executes the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Add all available commands
	rootCmd.AddCommand(modules.ReconCmd)
	rootCmd.AddCommand(modules.EtcdInjectCmd)
	rootCmd.AddCommand(modules.KubeletJackerCmd)
	rootCmd.AddCommand(modules.SidecarInjectCmd)
}
