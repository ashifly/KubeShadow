package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"os/exec"

	"github.com/spf13/cobra"
)

var LabCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Alias for 'lab destroy' — tear down the KubeShadow attack lab",
	Long:  `Tear down all KubeShadow lab resources. Delegates to terraform destroy in the kubeshadow-attack-labs repo.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		labsPath, _ := cmd.Flags().GetString("labs-path")

		labsDir, err := resolveLabsDir(labsPath)
		if err != nil {
			return err
		}

		return runTerraformDestroy(labsDir)
	},
}

func init() {
	LabCleanupCmd.Flags().String("labs-path", "", "Path to local kubeshadow-attack-labs checkout")
	LabCleanupCmd.Flags().String("provider", "minikube", "Provider used to provision the cluster")
	LabCleanupCmd.Flags().String("region", "", "Cloud region of the cluster")
	LabCleanupCmd.Flags().String("cluster-name", "kubeshadow-lab", "Cluster name")
	LabCleanupCmd.Flags().Bool("confirm", false, "Skip confirmation prompt")
}

// terraformStateExists checks if a terraform state file is present in the given directory.
func terraformStateExists(labsDir string) bool {
	_, err := os.Stat(filepath.Join(labsDir, "terraform.tfstate"))
	return err == nil
}

// runKubectl is a convenience wrapper for kubectl commands (used for status checks).
func runKubectl(args ...string) error {
	cmd := exec.Command("kubectl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// printLabStatus prints cluster pod/service status after deployment.
func printLabStatus() {
	fmt.Println("\n📊 Lab Status:")
	runKubectl("get", "pods", "-n", "kubeshadow-lab")
	fmt.Println("\n🌐 Services:")
	runKubectl("get", "services", "-n", "kubeshadow-lab")
}
