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

		region, err := cmd.Flags().GetString("region")
		if err != nil {
			return fmt.Errorf("failed to get region flag: %w", err)
		}

		fmt.Println("🧹 KubeShadow Lab Cleanup")
		fmt.Println("=========================")

		// For cloud providers, set default region if not provided
		if region == "" && contains([]string{"aws", "gcp", "azure"}, provider) {
			switch provider {
			case "aws":
				region = "us-west-2"
			case "gcp":
				region = "us-west2"
			case "azure":
				region = "eastus"
			}
		}

		if !confirm {
			if contains([]string{"aws", "gcp", "azure"}, provider) {
				fmt.Printf("⚠️  This will DELETE the entire cluster '%s' and ALL its resources in %s.\n", clusterName, region)
				fmt.Print("⚠️  This action CANNOT be undone. Continue? (y/N): ")
			} else {
				fmt.Print("⚠️  This will delete ALL lab resources. Continue? (y/N): ")
			}
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("❌ Cleanup cancelled.")
				return nil
			}
		}

		// Clean up cluster FIRST (before manifests, in case kubectl doesn't work)
		if contains([]string{"aws", "gcp", "azure", "minikube", "kind"}, provider) {
			fmt.Printf("🗑️  Removing %s cluster: %s\n", provider, clusterName)
			if err := cleanupCluster(provider, clusterName, region); err != nil {
				return fmt.Errorf("failed to cleanup cluster: %w", err)
			}
		}

		// Clean up lab manifests (only if kubectl is available)
		if err := cleanupLabManifests(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to cleanup lab manifests (cluster may already be deleted): %v\n", err)
		}

		fmt.Println("✅ Lab cleanup complete!")
		return nil
	},
}

func init() {
	LabCleanupCmd.Flags().Bool("confirm", false, "Skip confirmation prompt")
	LabCleanupCmd.Flags().String("provider", "local", "Provider to cleanup (aws, gcp, azure, minikube, kind, local)")
	LabCleanupCmd.Flags().String("cluster-name", "kubeshadow-lab", "Name of the cluster to cleanup")
	LabCleanupCmd.Flags().String("region", "", "Cloud region/zone (for cloud providers). For GCP, can be region like 'us-west2' or zone like 'us-west2-b'")
}

// cleanupLabManifests removes all lab resources
// This is optional and only runs if kubectl is available
func cleanupLabManifests() error {
	// Check if kubectl is available
	cmd := exec.Command("kubectl", "version", "--client", "--short")
	if err := cmd.Run(); err != nil {
		fmt.Println("⚠️  kubectl not available or not authenticated, skipping manifest cleanup")
		fmt.Println("   (Cluster deletion should have removed all resources)")
		return nil
	}

	fmt.Println("📦 Removing lab resources from cluster...")

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
			// Ignore errors as cluster may already be deleted
			continue
		}
	}

	// Wait for resources to be deleted (if cluster still exists)
	fmt.Println("⏳ Waiting for resources to be deleted...")
	cmd = exec.Command("kubectl", "wait", "--for=delete", "namespace/kubeshadow-lab", "--timeout=30s", "--ignore-not-found=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run() // Ignore errors

	return nil
}

// cleanupCluster removes the entire cluster
func cleanupCluster(provider, clusterName, region string) error {
	switch provider {
	case "aws":
		return cleanupAWSCluster(clusterName, region)
	case "gcp":
		return cleanupGCPCluster(clusterName, region)
	case "azure":
		return cleanupAzureCluster(clusterName, region)
	case "minikube":
		return cleanupMinikubeCluster()
	case "kind":
		return cleanupKindCluster(clusterName)
	}

	return fmt.Errorf("unsupported provider for cleanup: %s", provider)
}

// cleanupAWSCluster deletes EKS cluster
func cleanupAWSCluster(clusterName, region string) error {
	fmt.Printf("☁️  Deleting EKS cluster '%s' in region '%s'...\n", clusterName, region)

	cmd := exec.Command("eksctl", "delete", "cluster", "--name", clusterName, "--region", region, "--wait")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete EKS cluster: %w", err)
	}

	fmt.Printf("✅ EKS cluster '%s' deleted successfully\n", clusterName)
	return nil
}

// cleanupGCPCluster deletes GKE cluster
func cleanupGCPCluster(clusterName, region string) error {
	fmt.Printf("☁️  Deleting GKE cluster '%s'...\n", clusterName)

	// Normalize region format (convert us-west-2 to us-west2)
	region = normalizeGCPRegion(region)

	// Try to find the cluster and get its zone
	// First, try using gcloud to list clusters and find the exact location
	fmt.Println("   Searching for cluster location...")
	
	// Try listing clusters in common zones/regions to find the cluster
	zone := region + "-b" // Default zone format
	
	// Check if region is already a zone (contains -a, -b, -c)
	if strings.HasSuffix(region, "-a") || strings.HasSuffix(region, "-b") || strings.HasSuffix(region, "-c") {
		zone = region
	} else {
		// Try common zones: a, b, c
		zonesToTry := []string{region + "-b", region + "-a", region + "-c"}
		clusterFound := false
		
		for _, z := range zonesToTry {
			// Check if cluster exists in this zone
			checkCmd := exec.Command("gcloud", "container", "clusters", "describe", clusterName, "--zone", z, "--format", "value(name)", "--quiet")
			output, err := checkCmd.Output()
			if err == nil && strings.TrimSpace(string(output)) == clusterName {
				zone = z
				clusterFound = true
				fmt.Printf("   Found cluster in zone: %s\n", zone)
				break
			}
		}
		
		// If not found in zones, try as a region (regional cluster)
		if !clusterFound {
			fmt.Printf("   Cluster not found in zonal locations, trying as regional cluster in: %s\n", region)
			// Try regional deletion
			cmd := exec.Command("gcloud", "container", "clusters", "delete", clusterName, "--region", region, "--quiet")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to delete GKE cluster (tried as regional): %w", err)
			}
			fmt.Printf("✅ GKE cluster '%s' deleted successfully (regional cluster)\n", clusterName)
			return nil
		}
	}

	// Delete zonal cluster
	fmt.Printf("   Deleting cluster in zone: %s\n", zone)
	cmd := exec.Command("gcloud", "container", "clusters", "delete", clusterName, "--zone", zone, "--quiet")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete GKE cluster in zone %s: %w", zone, err)
	}

	fmt.Printf("✅ GKE cluster '%s' deleted successfully\n", clusterName)
	return nil
}

// cleanupAzureCluster deletes AKS cluster
func cleanupAzureCluster(clusterName, region string) error {
	fmt.Printf("☁️  Deleting AKS cluster '%s' in region '%s'...\n", clusterName, region)

	resourceGroup := clusterName + "-rg"
	
	// Delete AKS cluster
	cmd := exec.Command("az", "aks", "delete", "--resource-group", resourceGroup, "--name", clusterName, "--yes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// If resource group doesn't exist, that's okay
		if strings.Contains(err.Error(), "ResourceGroupNotFound") {
			fmt.Printf("   Resource group '%s' not found, cluster may already be deleted\n", resourceGroup)
			return nil
		}
		return fmt.Errorf("failed to delete AKS cluster: %w", err)
	}

	// Delete resource group (optional, but clean up everything)
	fmt.Printf("   Deleting resource group '%s'...\n", resourceGroup)
	cmd = exec.Command("az", "group", "delete", "--name", resourceGroup, "--yes", "--no-wait")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️  Warning: Failed to delete resource group: %v\n", err)
		// Don't fail the whole operation if resource group deletion fails
	}

	fmt.Printf("✅ AKS cluster '%s' deleted successfully\n", clusterName)
	return nil
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
