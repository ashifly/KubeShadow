package modules

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubeshadow",
	Short: "Kubernetes stealth offensive red team tool",
}

func init() {
	rootCmd.AddCommand(EtcdInjectCmd)
	rootCmd.AddCommand(KubeletJackerCmd)
	rootCmd.AddCommand(ReconCmd)
	rootCmd.AddCommand(SidecarInjectCmd)
	rootCmd.AddCommand(MetadataHijackCmd)
	rootCmd.AddCommand(CloudElevatorCmd)
	rootCmd.AddCommand(RBACEscalateCmd)
	rootCmd.AddCommand(AuditBypassCmd)
	rootCmd.AddCommand(DNSCachePoisonCmd)
	rootCmd.AddCommand(NamespacePivotCmd)
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}
