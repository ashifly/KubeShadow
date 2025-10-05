package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"kubeshadow/pkg/dashboard"

	"github.com/spf13/cobra"
)

// ClusterConfig represents cluster configuration options
type ClusterConfig struct {
	NumNodes    int
	MinNodes    int
	MaxNodes    int
	MachineType string
	DiskSize    string
	DiskType    string
}

var LabCmd = &cobra.Command{
	Use:   "lab",
	Short: "Deploy KubeShadow lab environment for security testing",
	Long: `Deploy a complete KubeShadow lab environment with intentionally vulnerable configurations
for hands-on security testing practice. Supports cloud providers and local environments.

Cluster size options (reduces costs and disk usage):
- minimal: 1 node, 20GB disk (t3.micro/e2-micro/Standard_B1s)
- small: 2 nodes, 50GB disk (t3.small/e2-small/Standard_B2s)  
- medium: 3 nodes, 100GB disk (t3.medium/e2-medium/Standard_B2ms)

Examples:
  kubeshadow lab --provider minikube
  kubeshadow lab --provider aws --cluster-size minimal --use-spot
  kubeshadow lab --provider gcp --cluster-size small --use-spot`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Create dashboard wrapper
		wrapper := dashboard.NewCommandWrapper(cmd, "lab", "lab", args)

		return wrapper.Execute(func() error {
			provider, err := cmd.Flags().GetString("provider")
			if err != nil {
				return fmt.Errorf("failed to get provider flag: %w", err)
			}

			region, err := cmd.Flags().GetString("region")
			if err != nil {
				return fmt.Errorf("failed to get region flag: %w", err)
			}

			clusterName, err := cmd.Flags().GetString("cluster-name")
			if err != nil {
				return fmt.Errorf("failed to get cluster-name flag: %w", err)
			}

			skipAuth, err := cmd.Flags().GetBool("skip-auth")
			if err != nil {
				return fmt.Errorf("failed to get skip-auth flag: %w", err)
			}

			clusterSize, err := cmd.Flags().GetString("cluster-size")
			if err != nil {
				return fmt.Errorf("failed to get cluster-size flag: %w", err)
			}

			useSpot, err := cmd.Flags().GetBool("use-spot")
			if err != nil {
				return fmt.Errorf("failed to get use-spot flag: %w", err)
			}

			fmt.Println("🎯 KubeShadow Lab Deployment")
			fmt.Println("================================")

			// Validate provider
			validProviders := []string{"aws", "gcp", "azure", "minikube", "kind", "local"}
			if !contains(validProviders, provider) {
				return fmt.Errorf("invalid provider: %s. Valid options: %s", provider, strings.Join(validProviders, ", "))
			}

			// Handle cloud providers
			if contains([]string{"aws", "gcp", "azure"}, provider) {
				if !skipAuth {
					fmt.Printf("🔐 Please authenticate with %s first:\n", strings.ToUpper(provider))
					if err := authenticateCloudProvider(provider); err != nil {
						return fmt.Errorf("authentication failed: %w", err)
					}
				}

				fmt.Printf("☁️  Deploying lab environment to %s...\n", strings.ToUpper(provider))
				fmt.Printf("📏 Cluster size: %s\n", clusterSize)
				if useSpot {
					fmt.Println("💰 Using spot instances for cost savings")
				}
				return deployCloudLab(provider, region, clusterName, clusterSize, useSpot)
			}

			// Handle local environments
			if contains([]string{"minikube", "kind", "local"}, provider) {
				fmt.Printf("🏠 Deploying lab environment to %s...\n", provider)
				return deployLocalLab(provider, clusterName)
			}

			return fmt.Errorf("unsupported provider: %s", provider)
		})
	},
}

func init() {
	LabCmd.Flags().String("provider", "minikube", "Cloud provider or local environment (aws, gcp, azure, minikube, kind, local)")
	LabCmd.Flags().String("region", "us-west-2", "Cloud region (for cloud providers)")
	LabCmd.Flags().String("cluster-name", "kubeshadow-lab", "Name for the Kubernetes cluster")
	LabCmd.Flags().Bool("skip-auth", false, "Skip cloud authentication (use existing credentials)")
	LabCmd.Flags().String("cluster-size", "minimal", "Cluster size: minimal (1 node, 20GB), small (2 nodes, 50GB), medium (3 nodes, 100GB)")
	LabCmd.Flags().Bool("use-spot", false, "Use spot instances for cost savings (cloud providers only)")

	// Add cleanup subcommand
	LabCmd.AddCommand(LabCleanupCmd)
}

// authenticateCloudProvider handles cloud provider authentication
func authenticateCloudProvider(provider string) error {
	switch provider {
	case "aws":
		fmt.Println("   Run: aws configure")
		fmt.Println("   Or: aws sso login")
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	case "gcp":
		fmt.Println("   Run: gcloud auth login")
		fmt.Println("   And: gcloud auth application-default login")
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	case "azure":
		fmt.Println("   Run: az login")
		fmt.Print("   Press Enter when authenticated...")
		fmt.Scanln()
	}
	return nil
}

// deployCloudLab deploys lab to cloud providers
func deployCloudLab(provider, region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Printf("🚀 Creating %s cluster: %s in region: %s\n", provider, clusterName, region)
	fmt.Printf("📏 Cluster size: %s\n", clusterSize)
	if useSpot {
		fmt.Println("💰 Using spot instances for cost savings")
	}

	switch provider {
	case "aws":
		return deployAWSLab(region, clusterName, clusterSize, useSpot)
	case "gcp":
		return deployGCPLab(region, clusterName, clusterSize, useSpot)
	case "azure":
		return deployAzureLab(region, clusterName, clusterSize, useSpot)
	}

	return fmt.Errorf("unsupported cloud provider: %s", provider)
}

// deployLocalLab deploys lab to local environments
func deployLocalLab(provider, clusterName string) error {
	fmt.Printf("🏠 Setting up %s environment: %s\n", provider, clusterName)

	switch provider {
	case "minikube":
		return deployMinikubeLab()
	case "kind":
		return deployKindLab(clusterName)
	case "local":
		return deployLocalK8sLab()
	}

	return fmt.Errorf("unsupported local provider: %s", provider)
}

// deployAWSLab creates EKS cluster and deploys lab
func deployAWSLab(region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Println("📦 Creating EKS cluster...")

	// Get cluster configuration based on size
	config := getClusterConfig(clusterSize, useSpot)
	fmt.Printf("💡 Using %s cluster configuration to reduce costs and disk usage...\n", clusterSize)
	fmt.Printf("📊 Nodes: %d, Instance: %s\n", config.NumNodes, config.MachineType)

	// Create EKS cluster with size-specific configuration
	args := []string{
		"create", "cluster",
		"--name", clusterName,
		"--region", region,
		"--nodegroup-name", "workers",
		"--node-type", config.MachineType,
		"--nodes", fmt.Sprintf("%d", config.NumNodes),
		"--nodes-min", fmt.Sprintf("%d", config.MinNodes),
		"--nodes-max", fmt.Sprintf("%d", config.MaxNodes),
		"--managed",
		"--with-oidc",
		"--ssh-access",
		"--ssh-public-key", "kubeshadow-lab",
		"--full-ecr-access",
	}

	// Add spot instance configuration if requested
	if useSpot {
		args = append(args, "--spot")
	}

	cmd := exec.Command("eksctl", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create EKS cluster: %w", err)
	}

	// Update kubeconfig
	cmd = exec.Command("aws", "eks", "update-kubeconfig", "--region", region, "--name", clusterName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update kubeconfig: %w", err)
	}

	return deployLabManifests()
}

// deployGCPLab creates GKE cluster and deploys lab
func deployGCPLab(region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Println("📦 Creating GKE cluster...")

	// Get cluster configuration based on size
	config := getGCPClusterConfig(clusterSize, useSpot)
	fmt.Printf("💡 Using %s cluster configuration to reduce costs and disk usage...\n", clusterSize)
	fmt.Printf("📊 Nodes: %d, Disk: %s, Machine: %s\n", config.NumNodes, config.DiskSize, config.MachineType)

	// Create GKE cluster with size-specific configuration
	args := []string{
		"container", "clusters", "create", clusterName,
		"--region", region,
		"--num-nodes", fmt.Sprintf("%d", config.NumNodes),
		"--machine-type", config.MachineType,
		"--disk-size", config.DiskSize,
		"--disk-type", config.DiskType,
		"--enable-autoscaling",
		"--min-nodes", fmt.Sprintf("%d", config.MinNodes),
		"--max-nodes", fmt.Sprintf("%d", config.MaxNodes),
		"--enable-autorepair",
		"--enable-autoupgrade",
		"--no-enable-ip-alias", // Disable VPC-native to reduce complexity
	}

	// Add spot instance configuration if requested
	if useSpot {
		args = append(args, "--preemptible")
	}

	cmd := exec.Command("gcloud", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create GKE cluster: %w", err)
	}

	// Get cluster credentials
	cmd = exec.Command("gcloud", "container", "clusters", "get-credentials", clusterName, "--region", region)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get cluster credentials: %w", err)
	}

	return deployLabManifests()
}

// deployAzureLab creates AKS cluster and deploys lab
func deployAzureLab(region, clusterName, clusterSize string, useSpot bool) error {
	fmt.Println("📦 Creating AKS cluster...")

	// Get cluster configuration based on size
	config := getAzureClusterConfig(clusterSize, useSpot)
	fmt.Printf("💡 Using %s cluster configuration to reduce costs and disk usage...\n", clusterSize)
	fmt.Printf("📊 Nodes: %d, Instance: %s\n", config.NumNodes, config.MachineType)

	// Create resource group
	resourceGroup := clusterName + "-rg"
	cmd := exec.Command("az", "group", "create", "--name", resourceGroup, "--location", region)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create resource group: %w", err)
	}

	// Create AKS cluster with size-specific configuration
	args := []string{
		"aks", "create",
		"--resource-group", resourceGroup,
		"--name", clusterName,
		"--node-count", fmt.Sprintf("%d", config.NumNodes),
		"--node-vm-size", config.MachineType,
		"--enable-addons", "monitoring",
		"--generate-ssh-keys",
	}

	// Add spot instance configuration if requested
	if useSpot {
		args = append(args, "--enable-ultra-ssd")
	}

	cmd = exec.Command("az", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create AKS cluster: %w", err)
	}

	// Get cluster credentials
	cmd = exec.Command("az", "aks", "get-credentials", "--resource-group", resourceGroup, "--name", clusterName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get cluster credentials: %w", err)
	}

	return deployLabManifests()
}

// deployMinikubeLab sets up minikube and deploys lab
func deployMinikubeLab() error {
	fmt.Println("📦 Starting minikube...")

	// Start minikube
	cmd := exec.Command("minikube", "start", "--driver=docker", "--memory=4096", "--cpus=2")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start minikube: %w", err)
	}

	// Enable addons
	addons := []string{"ingress", "metrics-server", "dashboard"}
	for _, addon := range addons {
		cmd = exec.Command("minikube", "addons", "enable", addon)
		if err := cmd.Run(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to enable addon %s: %v\n", addon, err)
		}
	}

	return deployLabManifests()
}

// deployKindLab sets up kind and deploys lab
func deployKindLab(clusterName string) error {
	fmt.Println("📦 Creating kind cluster...")

	// Create kind cluster config
	kindConfig := fmt.Sprintf(`kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: %s
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
- role: worker
- role: worker`, clusterName)

	configFile := "kind-config.yaml"
	if err := os.WriteFile(configFile, []byte(kindConfig), 0644); err != nil {
		return fmt.Errorf("failed to create kind config: %w", err)
	}
	defer os.Remove(configFile)

	// Create kind cluster
	cmd := exec.Command("kind", "create", "cluster", "--config", configFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create kind cluster: %w", err)
	}

	return deployLabManifests()
}

// deployLocalK8sLab deploys to existing local cluster
func deployLocalK8sLab() error {
	fmt.Println("📦 Deploying to existing local cluster...")

	// Check if kubectl can connect
	cmd := exec.Command("kubectl", "cluster-info")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot connect to local cluster: %w", err)
	}

	return deployLabManifests()
}

// deployLabManifests deploys all lab YAML files
func deployLabManifests() error {
	fmt.Println("🚀 Deploying lab manifests...")

	labDir := "modules/lab/manifests"
	yamlFiles := []string{
		"01-namespace.yaml",
		"02-rbac.yaml",
		"03-pods.yaml",
		"04-services.yaml",
		"05-secrets.yaml",
		"06-configmaps.yaml",
		"07-network-policies.yaml",
		"08-persistent-volumes.yaml",
		"09-ephemeral-containers.yaml",
		"10-secure-ephemeral.yaml",
		"13-chroot-escape.yaml",
		"14-secure-chroot.yaml",
		"15-highly-vulnerable.yaml",
	}

	for _, file := range yamlFiles {
		filePath := filepath.Join(labDir, file)
		fmt.Printf("   📄 Applying %s...\n", file)

		cmd := exec.Command("kubectl", "apply", "-f", filePath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to apply %s: %v\n", file, err)
		}
	}

	// Wait for pods to be ready
	fmt.Println("⏳ Waiting for pods to be ready...")
	cmd := exec.Command("kubectl", "wait", "--for=condition=Ready", "pod", "--all", "-n", "kubeshadow-lab", "--timeout=120s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️  Warning: Some pods may not be ready: %v\n", err)
	}

	// Display lab status
	fmt.Println("\n🎉 Lab deployment complete!")
	fmt.Println("\n📊 Lab Status:")

	cmd = exec.Command("kubectl", "get", "pods", "-n", "kubeshadow-lab")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println("\n🌐 Services:")
	cmd = exec.Command("kubectl", "get", "services", "-n", "kubeshadow-lab")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println("\n🔑 Secrets:")
	cmd = exec.Command("kubectl", "get", "secrets", "-n", "kubeshadow-lab")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println("\n🎓 Ready for KubeShadow exercises!")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Start KubeShadow dashboard: ./kubeshadow dashboard")
	fmt.Println("2. Run reconnaissance: ./kubeshadow recon --dashboard")
	fmt.Println("3. Explore the lab environment and identify security issues")
	fmt.Println("\nHappy learning! 🚀")

	return nil
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// getClusterConfig returns cluster configuration based on size and spot preferences
func getClusterConfig(clusterSize string, _ bool) ClusterConfig {
	switch clusterSize {
	case "minimal":
		return ClusterConfig{
			NumNodes:    1,
			MinNodes:    1,
			MaxNodes:    2,
			MachineType: "t3.micro", // Default to AWS, will be overridden per provider
			DiskSize:    "20GB",
			DiskType:    "gp2",
		}
	case "small":
		return ClusterConfig{
			NumNodes:    2,
			MinNodes:    1,
			MaxNodes:    3,
			MachineType: "t3.small",
			DiskSize:    "50GB",
			DiskType:    "gp2",
		}
	case "medium":
		return ClusterConfig{
			NumNodes:    3,
			MinNodes:    2,
			MaxNodes:    5,
			MachineType: "t3.medium",
			DiskSize:    "100GB",
			DiskType:    "gp2",
		}
	default:
		// Default to minimal for unknown sizes
		return ClusterConfig{
			NumNodes:    1,
			MinNodes:    1,
			MaxNodes:    2,
			MachineType: "t3.micro",
			DiskSize:    "20GB",
			DiskType:    "gp2",
		}
	}
}

// getGCPClusterConfig returns GCP-specific cluster configuration
func getGCPClusterConfig(clusterSize string, useSpot bool) ClusterConfig {
	config := getClusterConfig(clusterSize, useSpot)

	// Override with GCP-specific values
	switch clusterSize {
	case "minimal":
		config.MachineType = "e2-micro"
		config.DiskType = "pd-standard"
	case "small":
		config.MachineType = "e2-small"
		config.DiskType = "pd-standard"
	case "medium":
		config.MachineType = "e2-medium"
		config.DiskType = "pd-standard"
	}

	return config
}

// getAzureClusterConfig returns Azure-specific cluster configuration
func getAzureClusterConfig(clusterSize string, useSpot bool) ClusterConfig {
	config := getClusterConfig(clusterSize, useSpot)

	// Override with Azure-specific values
	switch clusterSize {
	case "minimal":
		config.MachineType = "Standard_B1s" // Azure: B1s (1 vCPU, 1 GB RAM)
		config.DiskType = "Premium_LRS"
	case "small":
		config.MachineType = "Standard_B2s" // Azure: B2s (2 vCPU, 4 GB RAM)
		config.DiskType = "Premium_LRS"
	case "medium":
		config.MachineType = "Standard_B2ms" // Azure: B2ms (2 vCPU, 8 GB RAM)
		config.DiskType = "Premium_LRS"
	}

	return config
}
