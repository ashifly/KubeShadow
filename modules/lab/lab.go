package lab

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const defaultLabsRepo = "https://github.com/ashifly/kubeshadow-attack-labs"
const defaultLabsDirName = "kubeshadow-attack-labs"

var LabCmd = &cobra.Command{
	Use:   "lab",
	Short: "Manage the KubeShadow attack lab environment",
	Long: `Deploy or destroy a complete vulnerable Kubernetes attack lab.

KubeShadow delegates lab orchestration to the kubeshadow-attack-labs repo,
which manages both cluster provisioning and Terraform-based manifest deployment.

Commands:
  kubeshadow lab apply    Deploy the full lab (or a single manifest)
  kubeshadow lab destroy  Tear down the lab

Examples:
  kubeshadow lab apply --provider minikube
  kubeshadow lab apply --provider aws --cluster-size minimal --use-spot
  kubeshadow lab apply --manifest 05-secrets.yaml
  kubeshadow lab destroy --provider minikube`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var labApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Deploy the KubeShadow attack lab",
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, _ := cmd.Flags().GetString("provider")
		region, _ := cmd.Flags().GetString("region")
		clusterName, _ := cmd.Flags().GetString("cluster-name")
		clusterSize, _ := cmd.Flags().GetString("cluster-size")
		useSpot, _ := cmd.Flags().GetBool("use-spot")
		manifest, _ := cmd.Flags().GetString("manifest")
		labsPath, _ := cmd.Flags().GetString("labs-path")

		labsDir, err := resolveLabsDir(labsPath)
		if err != nil {
			return err
		}

		fmt.Println("🎯 KubeShadow — Lab Deploy")
		fmt.Printf("📁 Labs directory: %s\n", labsDir)
		fmt.Printf("☸️  Provider: %s | Size: %s\n", provider, clusterSize)

		return runTerraformApply(labsDir, provider, region, clusterName, clusterSize, manifest, useSpot)
	},
}

var labDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Tear down the KubeShadow attack lab",
	RunE: func(cmd *cobra.Command, args []string) error {
		labsPath, _ := cmd.Flags().GetString("labs-path")
		confirm, _ := cmd.Flags().GetBool("confirm")

		if !confirm {
			fmt.Print("⚠️  This will destroy the lab. Continue? (y/N): ")
			var resp string
			fmt.Scanln(&resp)
			if strings.ToLower(resp) != "y" && strings.ToLower(resp) != "yes" {
				fmt.Println("❌ Destroy cancelled.")
				return nil
			}
		}

		labsDir, err := resolveLabsDir(labsPath)
		if err != nil {
			return err
		}

		fmt.Println("💥 KubeShadow — Lab Destroy")
		fmt.Printf("📁 Labs directory: %s\n", labsDir)

		return runTerraformDestroy(labsDir)
	},
}

func init() {
	// apply flags
	labApplyCmd.Flags().String("provider", "minikube", "Kubernetes provider: aws, gcp, azure, minikube, kind, local")
	labApplyCmd.Flags().String("region", "", "Cloud region (defaults: aws=us-west-2, gcp=us-west2, azure=eastus)")
	labApplyCmd.Flags().String("cluster-name", "kubeshadow-lab", "Cluster name")
	labApplyCmd.Flags().String("cluster-size", "minimal", "Cluster size: minimal, small, medium")
	labApplyCmd.Flags().Bool("use-spot", false, "Use spot/preemptible instances")
	labApplyCmd.Flags().String("manifest", "", "Deploy only a single manifest file (e.g. 05-secrets.yaml)")
	labApplyCmd.Flags().String("labs-path", "", "Path to local kubeshadow-attack-labs checkout (leave empty to be prompted)")

	// destroy flags
	labDestroyCmd.Flags().String("provider", "minikube", "Provider used to provision the cluster")
	labDestroyCmd.Flags().String("region", "", "Cloud region of the cluster")
	labDestroyCmd.Flags().String("cluster-name", "kubeshadow-lab", "Cluster name")
	labDestroyCmd.Flags().String("labs-path", "", "Path to local kubeshadow-attack-labs checkout")
	labDestroyCmd.Flags().Bool("confirm", false, "Skip confirmation prompt")

	LabCmd.AddCommand(labApplyCmd)
	LabCmd.AddCommand(labDestroyCmd)
}

// resolveLabsDir determines where the kubeshadow-attack-labs repo lives.
// If labsPath is given, use it. Otherwise prompt the user.
func resolveLabsDir(labsPath string) (string, error) {
	if labsPath != "" {
		if _, err := os.Stat(labsPath); err != nil {
			return "", fmt.Errorf("--labs-path does not exist: %s", labsPath)
		}
		return labsPath, nil
	}

	// Auto-detect sibling directory
	siblingDir := filepath.Join("..", defaultLabsDirName)
	if abs, err := filepath.Abs(siblingDir); err == nil {
		siblingDir = abs
	}

	if _, err := os.Stat(siblingDir); err == nil {
		fmt.Printf("✅ Found kubeshadow-attack-labs at: %s\n", siblingDir)
		return siblingDir, nil
	}

	// Prompt user
	fmt.Println("")
	fmt.Println("📦 No local kubeshadow-attack-labs directory found.")
	fmt.Printf("   Default repo: %s\n", defaultLabsRepo)
	fmt.Print("   Use default repo? [Y/n]: ")

	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))

	if resp == "" || resp == "y" || resp == "yes" {
		cloneDir := siblingDir
		fmt.Printf("🔄 Cloning %s → %s\n", defaultLabsRepo, cloneDir)
		cmd := exec.Command("git", "clone", defaultLabsRepo, cloneDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git clone failed: %w", err)
		}
		return cloneDir, nil
	}

	// User wants a custom path
	fmt.Print("   Enter path to your Terraform labs directory: ")
	customPath, _ := reader.ReadString('\n')
	customPath = strings.TrimSpace(customPath)
	if customPath == "" {
		return "", fmt.Errorf("no labs path provided")
	}
	if _, err := os.Stat(customPath); err != nil {
		return "", fmt.Errorf("path does not exist: %s", customPath)
	}
	return customPath, nil
}

// runTerraformApply runs terraform init + apply in the labs directory.
func runTerraformApply(labsDir, provider, region, clusterName, clusterSize, targetManifest string, useSpot bool) error {
	fmt.Println("📦 Running terraform init...")
	initCmd := exec.Command("terraform", "init", "-input=false")
	initCmd.Dir = labsDir
	initCmd.Stdout = os.Stdout
	initCmd.Stderr = os.Stderr
	if err := initCmd.Run(); err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	args := []string{"apply", "-auto-approve",
		"-var", fmt.Sprintf("provider_name=%s", provider),
		"-var", fmt.Sprintf("cluster_name=%s", clusterName),
		"-var", fmt.Sprintf("cluster_size=%s", clusterSize),
		"-var", fmt.Sprintf("use_spot=%v", useSpot),
	}
	if region != "" {
		args = append(args, "-var", fmt.Sprintf("region=%s", region))
	}
	if targetManifest != "" {
		args = append(args, "-var", fmt.Sprintf("target_manifest=%s", targetManifest))
		fmt.Printf("🎯 Deploying single manifest: %s\n", targetManifest)
	} else {
		fmt.Println("🚀 Deploying all lab environments via Terraform...")
	}

	applyCmd := exec.Command("terraform", args...)
	applyCmd.Dir = labsDir
	applyCmd.Stdout = os.Stdout
	applyCmd.Stderr = os.Stderr
	if err := applyCmd.Run(); err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	fmt.Println("\n🎉 Lab deployed! Start attacking:")
	fmt.Println("  kubeshadow recon")
	fmt.Println("  kubeshadow exploitation")
	return nil
}

// runTerraformDestroy runs terraform destroy in the labs directory, then removes the cluster.
func runTerraformDestroy(labsDir string) error {
	// Check if terraform state exists
	if _, err := os.Stat(filepath.Join(labsDir, "terraform.tfstate")); err == nil {
		fmt.Println("💥 Running terraform destroy...")
		cmd := exec.Command("terraform", "destroy", "-auto-approve")
		cmd.Dir = labsDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("⚠️  terraform destroy encountered issues: %v\n", err)
		}
	} else {
		fmt.Println("ℹ️  No terraform state found — skipping terraform destroy")
	}

	fmt.Println("✅ Lab teardown complete!")
	return nil
}
