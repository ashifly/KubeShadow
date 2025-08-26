package recon

import (
	"context"
	"fmt"

	"kubeshadow/pkg/recon"

	"github.com/spf13/cobra"
)

var ReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Perform cluster and cloud reconnaissance",
	RunE: func(cmd *cobra.Command, args []string) error {
		kubeconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return fmt.Errorf("failed to get kubeconfig flag: %w", err)
		}
		stealth, err := cmd.Flags().GetBool("stealth")
		if err != nil {
			return fmt.Errorf("failed to get stealth flag: %w", err)
		}
		cloudOnly, err := cmd.Flags().GetBool("cloud-only")
		if err != nil {
			return fmt.Errorf("failed to get cloud-only flag: %w", err)
		}
		k8sOnly, err := cmd.Flags().GetBool("k8s-only")
		if err != nil {
			return fmt.Errorf("failed to get k8s-only flag: %w", err)
		}
		showRBAC, err := cmd.Flags().GetBool("show-rbac")
		if err != nil {
			return fmt.Errorf("failed to get show-rbac flag: %w", err)
		}

		// Validate flags
		if cloudOnly && k8sOnly {
			return fmt.Errorf("cannot specify both cloud-only and k8s-only flags")
		}

		ctx := context.Background()
		var reconErrors []error

		if !cloudOnly {
			fmt.Println("🔍 Starting Kubernetes Recon...")
			if err := recon.K8sRecon(ctx, kubeconfig, stealth, showRBAC); err != nil {
				reconErrors = append(reconErrors, fmt.Errorf("Kubernetes recon failed: %w", err))
			}
		}

		if !k8sOnly {
			fmt.Println("☁️  Starting Cloud Metadata Recon...")
			if err := recon.CloudRecon(ctx, stealth); err != nil {
				reconErrors = append(reconErrors, fmt.Errorf("Cloud recon failed: %w", err))
			}
		}

		if len(reconErrors) > 0 {
			return fmt.Errorf("recon completed with errors: %v", reconErrors)
		}
		return nil
	},
}

func init() {
	ReconCmd.Flags().String("kubeconfig", "~/.kube/config", "Path to the kubeconfig file")
	ReconCmd.Flags().Bool("stealth", true, "Enable stealth mode (minimal API calls)")
	ReconCmd.Flags().Bool("cloud-only", false, "Perform only cloud metadata recon")
	ReconCmd.Flags().Bool("k8s-only", false, "Perform only Kubernetes API recon")
	ReconCmd.Flags().Bool("show-rbac", false, "Show detailed RBAC analysis (RoleBindings and ClusterRoleBindings)")
}
