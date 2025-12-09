package lab

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var LabCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up KubeShadow lab environment",
	Long: `Remove all KubeShadow lab resources from the current cluster.
This will delete all namespaces, pods, services, and other resources created by the lab.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Execute lab cleanup
		confirm, err := cmd.Flags().GetBool("confirm")
		if err != nil {
			return fmt.Errorf("failed to get confirm flag: %w", err)
		}

		provider, err := cmd.Flags().GetString("provider")
		if err != nil {
			return fmt.Errorf("failed to get provider flag: %w", err)
		}

		clusterName, err := cmd.Flags().GetString("cluster-name")
		if err != nil {
			return fmt.Errorf("failed to get cluster-name flag: %w", err)
		}

		fmt.Println("🧹 KubeShadow Lab Cleanup")
		fmt.Println("=========================")

		if !confirm {
			fmt.Print("⚠️  This will delete ALL lab resources. Continue? (y/N): ")
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("❌ Cleanup cancelled.")
				return nil
			}
		}

		// Clean up lab manifests
		if err := cleanupLabManifests(); err != nil {
			return fmt.Errorf("failed to cleanup lab manifests: %w", err)
		}

		// Clean up cluster if requested
		if contains([]string{"aws", "gcp", "azure", "minikube", "kind"}, provider) {
			fmt.Printf("🗑️  Removing %s cluster: %s\n", provider, clusterName)
			if err := cleanupCluster(provider, clusterName); err != nil {
				fmt.Printf("⚠️  Warning: Failed to cleanup cluster: %v\n", err)
			}
		}

		fmt.Println("✅ Lab cleanup complete!")
		return nil
	},
}

func init() {
	LabCleanupCmd.Flags().Bool("confirm", false, "Skip confirmation prompt")
	LabCleanupCmd.Flags().String("provider", "local", "Provider to cleanup (aws, gcp, azure, minikube, kind, local)")
	LabCleanupCmd.Flags().String("cluster-name", "kubeshadow-lab", "Name of the cluster to cleanup")
}

// cleanupLabManifests removes all lab resources
func cleanupLabManifests() error {
	fmt.Println("📦 Removing lab resources...")

	labDir := "modules/lab/manifests"
	yamlFiles := []string{
		"24-tls-bootstrap-azure.yaml",
		"23-cve-2025-5187-node-ownerreference.yaml",
		"22-cve-2025-1974-ingress-nginx-rce.yaml",
		"21-dns-poisoning.yaml",
		"20-crypto-miner.yaml",
		"19-supply-chain-attack.yaml",
		"18-container-escape.yaml",
		"17-ssrf-vulnerability.yaml",
		"16-owasp-comprehensive.yaml",
		"15-highly-vulnerable.yaml",
		"14-secure-chroot.yaml",
		"13-chroot-escape.yaml",
		"12-advanced-vulnerabilities.yaml",
		"11-ephemeral-attack-scenarios.yaml",
		"10-secure-ephemeral.yaml",
		"09-ephemeral-containers.yaml",
		"08-persistent-volumes.yaml",
		"07-network-policies.yaml",
		"06-configmaps.yaml",
		"05-secrets.yaml",
		"04-services.yaml",
		"03-pods.yaml",
		"02-rbac.yaml",
		"01-namespace.yaml",
	}

	for _, file := range yamlFiles {
		filePath := fmt.Sprintf("%s/%s", labDir, file)
		fmt.Printf("   🗑️  Removing %s...\n", file)

		cmd := exec.Command("kubectl", "delete", "-f", filePath, "--ignore-not-found=true")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to remove %s: %v\n", file, err)
		}
	}

	// Wait for resources to be deleted
	fmt.Println("⏳ Waiting for resources to be deleted...")
	cmd := exec.Command("kubectl", "wait", "--for=delete", "namespace/kubeshadow-lab", "--timeout=60s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️  Warning: Some resources may still exist: %v\n", err)
	}

	return nil
}

// cleanupCluster removes the entire cluster
func cleanupCluster(provider, clusterName string) error {
	switch provider {
	case "aws":
		return cleanupAWSCluster(clusterName)
	case "gcp":
		return cleanupGCPCluster(clusterName)
	case "azure":
		return cleanupAzureCluster(clusterName)
	case "minikube":
		return cleanupMinikubeCluster()
	case "kind":
		return cleanupKindCluster(clusterName)
	}

	return fmt.Errorf("unsupported provider for cleanup: %s", provider)
}

// cleanupAWSCluster deletes EKS cluster
func cleanupAWSCluster(clusterName string) error {
	fmt.Println("☁️  Deleting EKS cluster...")

	cmd := exec.Command("eksctl", "delete", "cluster", "--name", clusterName, "--wait")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// cleanupGCPCluster deletes GKE cluster
func cleanupGCPCluster(clusterName string) error {
	fmt.Println("☁️  Deleting GKE cluster...")

	// Get region from current context
	cmd := exec.Command("kubectl", "config", "current-context")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current context: %w", err)
	}

	// Extract zone from context (simplified) - zonal clusters use zones, not regions
	zone := "us-west1-b" // Default zone
	if strings.Contains(string(output), "us-central1") {
		zone = "us-central1-b"
	} else if strings.Contains(string(output), "us-east1") {
		zone = "us-east1-b"
	}

	cmd = exec.Command("gcloud", "container", "clusters", "delete", clusterName, "--zone", zone, "--quiet")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// cleanupAzureCluster deletes AKS cluster
func cleanupAzureCluster(clusterName string) error {
	fmt.Println("☁️  Deleting AKS cluster...")

	resourceGroup := clusterName + "-rg"
	cmd := exec.Command("az", "aks", "delete", "--resource-group", resourceGroup, "--name", clusterName, "--yes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete AKS cluster: %w", err)
	}

	// Delete resource group
	cmd = exec.Command("az", "group", "delete", "--name", resourceGroup, "--yes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// cleanupMinikubeCluster stops minikube
func cleanupMinikubeCluster() error {
	fmt.Println("🏠 Stopping minikube...")

	cmd := exec.Command("minikube", "stop")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// cleanupKindCluster deletes kind cluster
func cleanupKindCluster(clusterName string) error {
	fmt.Println("🏠 Deleting kind cluster...")

	cmd := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
